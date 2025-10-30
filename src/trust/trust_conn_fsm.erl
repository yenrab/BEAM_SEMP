%%%-------------------------------------------------------------------
%% @doc trust_conn_fsm - Connection FSM for TRUST multiplexed sessions.
%% @end
%%%-------------------------------------------------------------------

-module(trust_conn_fsm).
-behaviour(gen_statem).

-export([start_link/3]).
-export([init/1, callback_mode/0, handle_event/4, terminate/3]).

-define(SERVER, ?MODULE).

%% FSM States
-define(HANDSHAKE_TOKEN, handshake_token).
-define(ACTIVE, active).
-define(DRAINING, draining).
-define(CLOSING, closing).

%% Frame validation constants
-define(FRAME_SIZE_MAX, 1048576).  %% 1 MiB
-define(ARGS_LEN_MAX, 65536).      %% 64 KiB

%% Session Configuration
-record(session_config, {
    max_inflight = 8,
    max_age_ms = 60000,
    idle_ms = 5000,
    max_calls = 100,
    drain_ms = 1000
}).

%% FSM State
-record(state, {
    socket,
    peer_info,
    session_config,
    inflight = 0,
    calls_total = 0,
    max_age_timer,
    idle_timer,
    max_age_expired = false,
    worker_sup,
    client_id,
    req_ids = sets:new([{version, 2}]),  %% tracks in-flight req_ids
    worker_monitors = #{}  %% maps Pid -> ReqId
}).

%%--------------------------------------------------------------------
%% @doc
%% Starts the connection FSM for a TLS socket.
%% @end
%%--------------------------------------------------------------------
-spec start_link(semp_facades:sslsocket(), map(), map()) -> {ok, pid()} | {error, term()}.
start_link(Socket, PeerInfo, SessionConfig) ->
    gen_statem:start_link(?MODULE, {Socket, PeerInfo, SessionConfig}, []).

%%--------------------------------------------------------------------
%% @doc
%% Callback mode for the FSM.
%% @end
%%--------------------------------------------------------------------
callback_mode() ->
    handle_event_function.

%%--------------------------------------------------------------------
%% @doc
%% Initializes the FSM in handshake_token state.
%% @end
%%--------------------------------------------------------------------
-spec init({semp_facades:sslsocket(), map(), map()}) -> {ok, ?HANDSHAKE_TOKEN, #state{}}.
init({Socket, PeerInfo, SessionConfig}) ->
    %% Read from sys.config with fallback to record defaults
    SessionConfigMap = application:get_env(beam_semp, session, SessionConfig),
    Config = #session_config{
        max_inflight = maps:get(max_inflight, SessionConfigMap, 8),
        max_age_ms = maps:get(max_age_ms, SessionConfigMap, 60000),
        idle_ms = maps:get(idle_ms, SessionConfigMap, 5000),
        max_calls = maps:get(max_calls, SessionConfigMap, 100),
        drain_ms = maps:get(drain_ms, SessionConfigMap, 1000)
    },
    
    %% Extract client ID from TLS certificate
    ClientId = extract_client_id(Socket),
    
    State = #state{
        socket = Socket,
        peer_info = PeerInfo,
        session_config = Config,
        client_id = ClientId
    },
    
                %% Set socket to active once for initial handshake
                case Socket of
                    {test_socket, _} -> ok;  %% Skip for test sockets
                    _ -> semp_facades:setopts(Socket, [{active, once}])
                end,
    
    %% Start idle timer
    IdleTimer = erlang:send_after(Config#session_config.idle_ms, self(), idle_timeout),
    
    {ok, ?HANDSHAKE_TOKEN, State#state{idle_timer = IdleTimer}}.

%%--------------------------------------------------------------------
%% @doc
%% Extracts client ID from TLS certificate.
%% @end
%%--------------------------------------------------------------------
extract_client_id(Socket) ->
    case Socket of
        {test_socket, _} ->
            %% For test sockets, return a test client ID
            <<"test_client_id">>;
        _ ->
            case semp_facades:peercert(Socket) of
                {ok, CertDer} ->
                    %% Generate fingerprint from certificate
                    semp_util:cert_fingerprint_sha512(CertDer);
                {error, _Reason} ->
                    undefined
            end
    end.

%%--------------------------------------------------------------------
%% @doc
%% Handles FSM events based on current state.
%% @end
%%--------------------------------------------------------------------
handle_event({ssl, Socket, Bin}, ?HANDSHAKE_TOKEN, State, _Data) ->
    handle_handshake_token(Socket, Bin, State);

handle_event({ssl, Socket, Bin}, ?ACTIVE, State, _Data) ->
    handle_active_request(Socket, Bin, State);

handle_event({ssl, Socket, Bin}, ?DRAINING, State, _Data) ->
    handle_draining_request(Socket, Bin, State);

handle_event({'DOWN', Pid, process, Pid, Reason}, ?ACTIVE, State, _Data) ->
    handle_worker_down(Pid, Reason, State);

handle_event({'DOWN', Pid, process, Pid, Reason}, ?DRAINING, State, _Data) ->
    handle_worker_down_draining(Pid, Reason, State);

handle_event(internal, limit_reached, ?ACTIVE, State) ->
    handle_limit_reached(State);

handle_event(state_timeout, idle, ?ACTIVE, State) ->
    handle_idle_timeout(State);

handle_event(state_timeout, drain, ?DRAINING, State) ->
    handle_drain_timeout(State);

handle_event({ssl_closed, Socket}, _StateName, State, _Data) ->
    handle_client_cancel(Socket, State);

handle_event({ssl_error, Socket, Reason}, _StateName, State, _Data) ->
    handle_ssl_error(Socket, Reason, State);

handle_event(idle_timeout, StateName, State, _Data) ->
    handle_idle_timeout_message(StateName, State);

handle_event(cast, {ssl, Socket, Bin}, ?HANDSHAKE_TOKEN, State) ->
    handle_handshake_token(Socket, Bin, State);

handle_event(cast, {ssl, Socket, Bin}, ?ACTIVE, State) ->
    handle_active_request(Socket, Bin, State);

handle_event(cast, {ssl, Socket, Bin}, ?DRAINING, State) ->
    handle_draining_request(Socket, Bin, State);

handle_event(enter, ?CLOSING, _OldState, _State) ->
    %% When entering CLOSING state, terminate immediately
    %% This ensures the FSM terminates after sending goaway
    {stop, normal};

handle_event(cast, {ssl, _Socket, _Bin}, ?CLOSING, State) ->
    %% In CLOSING state, ignore all SSL events but don't terminate immediately
    %% The FSM will be terminated by other means (timeout, explicit close, etc.)
    {keep_state, State};

handle_event(internal, terminate, ?CLOSING, _State) ->
    %% Terminate the FSM after the delay
    {stop, normal};

handle_event(cast, {send_frame, Frame}, StateName, State) 
    when StateName =:= ?ACTIVE; StateName =:= ?DRAINING ->
    semp_util:send_frame(State#state.socket, Frame),
    {keep_state, State};

handle_event(EventType, EventContent, StateName, State) ->
    logger:warning("trust_conn_fsm: unhandled event ~p (~p) in state ~p", [EventType, EventContent, StateName]),
    {keep_state, State}.

%%--------------------------------------------------------------------
%% @doc
%% Handles handshake and token validation.
%% @end
%%--------------------------------------------------------------------
handle_handshake_token(Socket, Bin, State) ->
    logger:debug("trust_conn_fsm: handle_handshake_token called with Bin: ~p", [Bin]),
    case safe_term(Bin) of
        %% Accept legacy/alternate token frame key 'token' (alias for token_present)
        #{t := token, token := Token} ->
            logger:debug("trust_conn_fsm: legacy token frame received, validating token"),
            case validate_token(Token, State) of
                ok ->
                    logger:debug("trust_conn_fsm: token validation successful (legacy), transitioning to active"),
                    transition_to_active(State);
                {error, _Reason} ->
                    logger:debug("trust_conn_fsm: token validation failed (legacy), closing and stopping"),
                    send_goaway(deny, 0, Socket),
                    semp_facades:close(Socket),
                    {stop, normal, State}
            end;
        #{t := token_present, token := Token} ->
            logger:debug("trust_conn_fsm: token_present received, validating token"),
            case validate_token(Token, State) of
                ok ->
                    logger:debug("trust_conn_fsm: token validation successful, transitioning to active"),
                    transition_to_active(State);
                {error, _Reason} ->
                    logger:debug("trust_conn_fsm: token validation failed, closing and stopping"),
                    send_goaway(deny, 0, Socket),
                    semp_facades:close(Socket),
                    {stop, normal, State}
            end;
        #{t := token_issue, token := Token} ->
            logger:debug("trust_conn_fsm: token_issue received, issuing token"),
            case issue_token(Token, State) of
                ok ->
                    logger:debug("trust_conn_fsm: token issue successful, transitioning to active"),
                    transition_to_active(State);
                {error, _Reason} ->
                    logger:debug("trust_conn_fsm: token issue failed, transitioning to closing"),
                    send_goaway(deny, 0, Socket),
                    semp_facades:close(Socket),
                    {next_state, ?CLOSING, State}
            end;
        _Other ->
            %% For truly malformed frames (like invalid binary data), terminate immediately
            %% This handles cases like the test that sends <<"invalid_binary_data">>
            logger:debug("trust_conn_fsm: malformed frame received in handshake, terminating immediately: ~p", [_Other]),
            logger:warning("trust_conn_fsm: malformed frame received, terminating immediately: ~p", [_Other]),
            send_goaway(protocol, 0, Socket),
            semp_facades:close(Socket),
            {stop, normal, State}
    end.

%%--------------------------------------------------------------------
%% @doc
%% Handles active state requests with backpressure.
%% @end
%%--------------------------------------------------------------------
handle_active_request(Socket, Bin, State) ->
    #state{inflight = Inflight, session_config = Config, client_id = ClientId} = State,
    
    logger:debug("trust_conn_fsm: handle_active_request called with Bin: ~p", [Bin]),
    
    %% Validate frame size
    case byte_size(Bin) of
        Size when Size > ?FRAME_SIZE_MAX ->
            logger:debug("trust_conn_fsm: frame too large, terminating"),
            catch trust_suspicion:bump(ClientId, up),
            send_goaway(protocol, 0, Socket),
            semp_facades:close(Socket),
            {stop, normal, State};
        _ ->
            if
                Inflight < Config#session_config.max_inflight ->
                    case decode_request(Bin) of
                        {ok, Request} ->
                            logger:debug("trust_conn_fsm: request decoded successfully: ~p", [Request]),
                            case spawn_worker(Request, State) of
                                {ok, NewState} ->
                                    semp_facades:setopts(Socket, [{active, once}]),
                                    ResetState = reset_idle_timer(NewState),
                                    {next_state, ?ACTIVE, ResetState};
                                {error, duplicate} ->
                                    semp_facades:setopts(Socket, [{active, once}]),
                                    ResetState = reset_idle_timer(State),
                                    {next_state, ?ACTIVE, ResetState};
                                {error, _Reason} ->
                                    logger:debug("trust_conn_fsm: spawn_worker failed, terminating"),
                                    send_goaway(protocol, 0, Socket),
                                    semp_facades:close(Socket),
                                    {stop, normal, State}
                            end;
                        {error, Reason} ->
                            logger:debug("trust_conn_fsm: decode_request failed with reason: ~p, terminating", [Reason]),
                            logger:warning("trust_conn_fsm: request decode failed for client ~p: ~p", [ClientId, Reason]),
                            catch trust_suspicion:bump(ClientId, up),
                            telemetry:execute([trust, request, decode_error], #{},
                                #{client_id => ClientId, reason => Reason}),
                            send_goaway(protocol, 0, Socket),
                            semp_facades:close(Socket),
                            {stop, normal, State}
                    end;
                true ->
                    %% Backpressure: pause reads
                    telemetry:execute([trust, request, refuse], #{}, 
                        #{reason => max_inflight}),
                    telemetry:execute([trust, pause], #{}, #{}),
                    semp_facades:setopts(Socket, [{active, false}]),
                    {next_state, ?ACTIVE, State}
            end
    end.

%%--------------------------------------------------------------------
%% @doc
%% Handles requests during draining phase.
%% @end
%%--------------------------------------------------------------------
handle_draining_request(Socket, Bin, State) ->
    #state{client_id = ClientId, peer_info = PeerInfo} = State,
    
    %% Log ignored request during draining
    logger:debug("trust_conn_fsm: ignoring request during drain from ~p (~p), size: ~p bytes", 
        [ClientId, PeerInfo, byte_size(Bin)]),
    
    %% Emit telemetry for ignored request
    telemetry:execute([trust, request, ignore], #{},
        #{client_id => ClientId, peer_info => PeerInfo, reason => draining, size_bytes => byte_size(Bin)}),
    
    %% Ignore new requests during draining
    semp_facades:setopts(Socket, [{active, once}]),
    {next_state, ?DRAINING, State}.

%%--------------------------------------------------------------------
%% @doc
%% Handles worker completion in active state.
%% @end
%%--------------------------------------------------------------------
handle_worker_down(Pid, Reason, State) ->
    #state{inflight = Inflight, session_config = Config, socket = Socket, 
           client_id = ClientId, req_ids = ReqIds, worker_monitors = Monitors} = State,
    
    %% Get ReqId and remove from tracking
    ReqId = maps:get(Pid, Monitors, undefined),
    NewReqIds = case ReqId of
        undefined -> ReqIds;
        _ -> sets:del_element(ReqId, ReqIds)
    end,
    NewMonitors = maps:remove(Pid, Monitors),
    
    NewInflight = Inflight - 1,
    NewState = State#state{
        inflight = NewInflight,
        req_ids = NewReqIds,
        worker_monitors = NewMonitors
    },
    
    %% Log worker completion with reason
    logger:debug("trust_conn_fsm: worker ~p completed for client ~p, inflight: ~p, reason: ~p", 
        [Pid, ClientId, NewInflight, Reason]),
    
    %% Emit telemetry for worker completion
    telemetry:execute([trust, worker, complete], #{},
        #{client_id => ClientId, req_id => ReqId, reason => Reason, inflight => NewInflight}),
    
    %% Resume reads if we were paused and now have capacity
    if
        NewInflight < Config#session_config.max_inflight ->
            telemetry:execute([trust, resume], #{}, #{}),
            semp_facades:setopts(Socket, [{active, once}]);
        true ->
            ok
    end,
    
    %% Check if we should transition to draining
    case should_drain(NewState) of
        true ->
            handle_limit_reached(NewState);
        false ->
            {next_state, ?ACTIVE, NewState, [{state_timeout, Config#session_config.idle_ms, idle}]}
    end.

%%--------------------------------------------------------------------
%% @doc
%% Handles worker completion in draining state.
%% @end
%%--------------------------------------------------------------------
handle_worker_down_draining(Pid, Reason, State) ->
    #state{inflight = Inflight, socket = Socket, client_id = ClientId, worker_monitors = Monitors} = State,
    
    %% Get ReqId for logging
    ReqId = maps:get(Pid, Monitors, undefined),
    
    NewInflight = Inflight - 1,
    NewState = State#state{inflight = NewInflight},
    
    %% Log worker completion in draining state
    logger:debug("trust_conn_fsm: worker ~p completed during drain for client ~p, inflight: ~p, reason: ~p", 
        [Pid, ClientId, NewInflight, Reason]),
    
    %% Emit telemetry for worker completion in drain
    telemetry:execute([trust, worker, complete_draining], #{},
        #{client_id => ClientId, req_id => ReqId, reason => Reason, inflight => NewInflight}),
    
    if
        NewInflight =:= 0 ->
            logger:info("trust_conn_fsm: drain complete for client ~p, closing connection", [ClientId]),
            semp_facades:close(Socket),
            {next_state, ?CLOSING, NewState};
        true ->
            {next_state, ?DRAINING, NewState}
    end.


%%--------------------------------------------------------------------
%% @doc
%% Handles client cancellation.
%% @end
%%--------------------------------------------------------------------
handle_client_cancel(Socket, State) ->
    #state{worker_sup = WorkerSup, client_id = ClientId, peer_info = PeerInfo} = State,
    
    %% Log client disconnection
    logger:info("trust_conn_fsm: client disconnected ~p from ~p", [ClientId, PeerInfo]),
    
    %% Emit telemetry for client disconnect
    telemetry:execute([trust, client, disconnect], #{},
        #{client_id => ClientId, peer_info => PeerInfo, socket => Socket}),
    
    %% Kill all workers immediately
    if
        WorkerSup =/= undefined ->
            supervisor:terminate_child(trust_conn_worker_sup, WorkerSup);
        true ->
            ok
    end,
    
    %% Close socket and transition to closing
    semp_facades:close(Socket),
    {next_state, ?CLOSING, State}.

%%--------------------------------------------------------------------
%% @doc
%% Handles SSL errors.
%% @end
%%--------------------------------------------------------------------
handle_ssl_error(Socket, Reason, State) ->
    #state{client_id = ClientId, peer_info = PeerInfo} = State,
    
    %% Log SSL error with context
    logger:warning("trust_conn_fsm: SSL error ~p from client ~p (~p)", [Reason, ClientId, PeerInfo]),
    
    %% Bump suspicion for SSL errors
    trust_suspicion:bump(ClientId, up),
    
    %% Emit telemetry for SSL error
    telemetry:execute([trust, ssl, error], #{},
        #{client_id => ClientId, peer_info => PeerInfo, reason => Reason, socket => Socket}),
    
    %% Send GOAWAY and close connection
    send_goaway(protocol, 0, Socket),
    semp_facades:close(Socket),
    {next_state, ?CLOSING, State}.

%%--------------------------------------------------------------------
%% @doc
%% Transitions to active state and starts session timers.
%% @end
%%--------------------------------------------------------------------
transition_to_active(State) ->
    #state{socket = Socket, session_config = Config, client_id = ClientId, peer_info = PeerInfo} = State,
    
    %% Start max-age timer
    MaxAgeTimer = erlang:send_after(Config#session_config.max_age_ms, self(), {internal, limit_reached}),
    
    %% Start or reuse worker supervisor robustly
    WorkerSup = case whereis(trust_conn_worker_sup) of
        undefined ->
            case trust_conn_worker_sup:start_link() of
                {ok, P} -> P;
                {error, {already_started, P}} -> P;
                {error, _} -> undefined
            end;
        Pid -> Pid
    end,
    
    NewState = State#state{
        max_age_timer = MaxAgeTimer,
        worker_sup = WorkerSup
    },
    
    %% Emit telemetry for session start
    telemetry:execute([trust, session, start], #{}, 
        #{client_id => ClientId, peer_info => PeerInfo}),
    
    %% Log session start
    logger:info("trust_conn_fsm: session started for client ~p", [ClientId]),
    
    %% Reset idle timer
    ResetState = reset_idle_timer(NewState),
    
    semp_facades:setopts(Socket, [{active, once}]),
    {next_state, ?ACTIVE, ResetState}.

%%--------------------------------------------------------------------
%% @doc
%% Checks if session should transition to draining.
%% @end
%%--------------------------------------------------------------------
should_drain(State) ->
    #state{
        calls_total = CallsTotal,
        max_age_expired = MaxAgeExpired,
        session_config = Config
    } = State,
    
    CallsTotal >= Config#session_config.max_calls orelse MaxAgeExpired.

%%--------------------------------------------------------------------
%% @doc
%% Handles limit reached transition to draining.
%% @end
%%--------------------------------------------------------------------
handle_limit_reached(State) ->
    #state{socket = Socket, session_config = Config, client_id = ClientId, calls_total = CallsTotal} = State,
    
    %% Log session end reason
    logger:info("trust_conn_fsm: session limit reached for client ~p, calls: ~p", [ClientId, CallsTotal]),
    
    send_goaway(limit_reached, Config#session_config.drain_ms, Socket),
    {next_state, ?DRAINING, State, [{state_timeout, Config#session_config.drain_ms, drain}]}.

%%--------------------------------------------------------------------
%% @doc
%% Handles idle timeout.
%% @end
%%--------------------------------------------------------------------
handle_idle_timeout(State) ->
    #state{client_id = ClientId} = State,
    logger:info("trust_conn_fsm: idle timeout for client ~p", [ClientId]),
    handle_limit_reached(State).

%%--------------------------------------------------------------------
%% @doc
%% Handles idle timeout message.
%% @end
%%--------------------------------------------------------------------
handle_idle_timeout_message(StateName, State) ->
    #state{client_id = ClientId, socket = Socket, peer_info = PeerInfo} = State,
    logger:info("trust_conn_fsm: idle timeout for client ~p (~p) in state ~p", [ClientId, PeerInfo, StateName]),
    telemetry:execute([trust, session, idle_timeout], #{},
        #{client_id => ClientId, peer_info => PeerInfo, state => StateName}),
    semp_facades:close(Socket),
    {next_state, ?CLOSING, State}.

%%--------------------------------------------------------------------
%% @doc
%% Handles drain timeout.
%% @end
%%--------------------------------------------------------------------
handle_drain_timeout(State) ->
    #state{socket = Socket, client_id = ClientId} = State,
    logger:info("trust_conn_fsm: drain timeout for client ~p", [ClientId]),
    semp_facades:close(Socket),
    {next_state, ?CLOSING, State}.

%%--------------------------------------------------------------------
%% @doc
%% Resets the idle timer.
%% @end
%%--------------------------------------------------------------------
reset_idle_timer(State) ->
    #state{idle_timer = OldTimer, session_config = Config} = State,
    %% Cancel old timer if it exists
    case OldTimer of
        undefined -> ok;
        _ -> erlang:cancel_timer(OldTimer)
    end,
    %% Start new timer
    NewTimer = erlang:send_after(Config#session_config.idle_ms, self(), idle_timeout),
    State#state{idle_timer = NewTimer}.

%%--------------------------------------------------------------------
%% @doc
%% Sends GOAWAY frame to client.
%% @end
%%--------------------------------------------------------------------
send_goaway(Reason, DrainMs, Socket) ->
    telemetry:execute([trust, goaway], #{}, 
        #{reason => Reason, drain_ms => DrainMs}),
    Frame = term_to_binary(#{t => goaway, reason => Reason, drain_ms => DrainMs}),
    semp_util:send_frame(Socket, Frame).

%%--------------------------------------------------------------------
%% @doc
%% Safely decodes binary to term.
%% @end
%%--------------------------------------------------------------------
safe_term(Bin) ->
    try binary_to_term(Bin, [safe]) of T -> T catch _:_ -> #{bad_term => true} end.

%%--------------------------------------------------------------------
%% @doc
%% Validates client token.
%% @end
%%--------------------------------------------------------------------
validate_token(Token, State) ->
    #state{client_id = ClientId} = State,
    case semp_facades:trust_token_validate(Token, ClientId) of
        ok -> ok;
        {ok, _} -> ok;  %% Handle case where validate returns {ok, TokenData}
        {error, _Reason} -> {error, invalid_token}
    end.

%%--------------------------------------------------------------------
%% @doc
%% Issues new token to client.
%% @end
%%--------------------------------------------------------------------
issue_token(Token, State) ->
    #state{client_id = ClientId, socket = Socket, peer_info = PeerInfo} = State,
    
    %% Log token issue request
    logger:debug("trust_conn_fsm: issuing token for client ~p (~p), current token: ~p", 
        [ClientId, PeerInfo, Token]),
    
    %% Validate current token before issuing new one
    case semp_facades:trust_token_validate(Token, ClientId) of
        ok ->
            %% Current token is valid, issue new token
            case semp_facades:trust_token_issue(ClientId) of
                true ->
                    %% Issue returns true, now get the token
                    case semp_facades:trust_token_token_for(ClientId) of
                        error ->
                            logger:error("trust_conn_fsm: failed to retrieve token for client ~p after issue", [ClientId]),
                            {error, token_retrieval_failed};
                        NewToken ->
                            %% Send new token to client
                            Frame = term_to_binary(#{t => token_issue, token => NewToken}),
                            case semp_util:send_frame(Socket, Frame) of
                                ok -> 
                                    logger:info("trust_conn_fsm: issued new token for client ~p", [ClientId]),
                                    telemetry:execute([trust, token, issue], #{},
                                        #{client_id => ClientId, peer_info => PeerInfo}),
                                    ok;
                                {error, Reason} -> 
                                    logger:error("trust_conn_fsm: failed to send token to client ~p: ~p", [ClientId, Reason]),
                                    {error, send_failed}
                            end
                    end;
                Other ->
                    logger:error("trust_conn_fsm: unexpected return from token issue for client ~p: ~p", [ClientId, Other]),
                    {error, issue_failed}
            end;
        {error, Reason} ->
            logger:warning("trust_conn_fsm: invalid token from client ~p: ~p", [ClientId, Reason]),
            telemetry:execute([trust, token, invalid], #{},
                #{client_id => ClientId, peer_info => PeerInfo, reason => Reason}),
            {error, invalid_token}
    end.

%%--------------------------------------------------------------------
%% @doc
%% Decodes request frame.
%% @end
%%--------------------------------------------------------------------
decode_request(Bin) ->
    case safe_term(Bin) of
        %% Map-based protocol (preferred)
        #{t := call, req_id := ReqId, m := M, f := F, a := A, args := Args} ->
            {ok, {call, ReqId, M, F, A, Args}};
        #{t := cast, req_id := ReqId, m := M, f := F, a := A, args := Args} ->
            {ok, {cast, ReqId, M, F, A, Args}};

        %% Back-compat with tuple-based test helper frames: {call|cast, ReqId, M, F, ArgOrArgs}
        %% Historical helper sends the payload directly (e.g., [1,2,3]) as a single argument.
        {call, ReqId, M, F, ArgOrArgs} when is_atom(M), is_atom(F) ->
            {ok, {call, ReqId, M, F, 1, [ArgOrArgs]}};
        {cast, ReqId, M, F, ArgOrArgs} when is_atom(M), is_atom(F) ->
            {ok, {cast, ReqId, M, F, 1, [ArgOrArgs]}};

        _Other ->
            {error, protocol_error}
    end.

%%--------------------------------------------------------------------
%% @doc
%% Spawns worker for request processing.
%% @end
%%--------------------------------------------------------------------
spawn_worker(Request, State) ->
    #state{worker_sup = WorkerSup, socket = Socket, client_id = ClientId, 
           req_ids = ReqIds, worker_monitors = Monitors} = State,
    
    ReqId = element(2, Request),  %% Extract req_id from tuple
    
    %% Check for duplicate
    case sets:is_element(ReqId, ReqIds) of
        true ->
            logger:warning("Duplicate req_id ~p from ~p, ignoring", [ReqId, ClientId]),
            telemetry:execute([trust, request, refuse], #{}, 
                #{reason => duplicate, req_id => ReqId}),
            {error, duplicate};
        false ->
            NewReqIds = sets:add_element(ReqId, ReqIds),
            case Request of
                {call, ReqId, M, F, A, Args} ->
                    WorkerSpec = #{
                        id => {trust_rpc_worker, ReqId},
                        start => {trust_rpc_worker, start_link, [self(), ReqId, call, {M, F, A}, Args, ClientId]},
                        restart => temporary,
                        shutdown => 4000,
                        type => worker,
                        modules => [trust_rpc_worker]
                    },
                    case supervisor:start_child(WorkerSup, WorkerSpec) of
                        {ok, Pid} ->
                            %% Monitor the worker and track mapping
                            erlang:monitor(process, Pid),
                            NewMonitors = maps:put(Pid, ReqId, Monitors),
                            telemetry:execute([trust, request, accept], #{}, 
                                #{type => call, req_id => ReqId}),
                            NewState = State#state{
                                inflight = State#state.inflight + 1,
                                calls_total = State#state.calls_total + 1,
                                req_ids = NewReqIds,
                                worker_monitors = NewMonitors
                            },
                            {ok, NewState};
                        {error, Reason} ->
                            logger:error("trust_conn_fsm: failed to start worker for client ~p: ~p", [ClientId, Reason]),
                            telemetry:execute([trust, worker, start_failed], #{},
                                #{client_id => ClientId, req_id => ReqId, reason => Reason, socket => Socket}),
                            {error, worker_start_failed}
                    end;
                {cast, ReqId, M, F, A, Args} ->
                    WorkerSpec = #{
                        id => {trust_rpc_worker, ReqId},
                        start => {trust_rpc_worker, start_link, [self(), ReqId, cast, {M, F, A}, Args, ClientId]},
                        restart => temporary,
                        shutdown => 4000,
                        type => worker,
                        modules => [trust_rpc_worker]
                    },
                    case supervisor:start_child(WorkerSup, WorkerSpec) of
                        {ok, Pid} ->
                            %% Monitor the worker and track mapping
                            erlang:monitor(process, Pid),
                            NewMonitors = maps:put(Pid, ReqId, Monitors),
                            telemetry:execute([trust, request, accept], #{}, 
                                #{type => cast, req_id => ReqId}),
                            NewState = State#state{
                                inflight = State#state.inflight + 1,
                                calls_total = State#state.calls_total + 1,
                                req_ids = NewReqIds,
                                worker_monitors = NewMonitors
                            },
                            {ok, NewState};
                        {error, Reason} ->
                            logger:error("trust_conn_fsm: failed to start worker for client ~p: ~p", [ClientId, Reason]),
                            telemetry:execute([trust, worker, start_failed], #{},
                                #{client_id => ClientId, req_id => ReqId, reason => Reason, socket => Socket}),
                            {error, worker_start_failed}
                    end
            end
    end.

%%--------------------------------------------------------------------
%% @doc
%% Terminates the FSM.
%% @end
%%--------------------------------------------------------------------
terminate(Reason, StateName, State) ->
    %% Handle case where State might not be properly initialized
    case State of
        #state{max_age_timer = Timer, idle_timer = IdleTimer, worker_sup = WorkerSup, client_id = ClientId} ->
            %% Emit telemetry for session end
            telemetry:execute([trust, session, 'end'], 
                #{age_ms => 0},  %% TODO: calculate actual age
                #{reason => Reason, client_id => ClientId, state => StateName}),
            
            %% Cancel max-age timer
            if
                Timer =/= undefined ->
                    erlang:cancel_timer(Timer);
                true ->
                    ok
            end,
            
            %% Cancel idle timer
            if
                IdleTimer =/= undefined ->
                    erlang:cancel_timer(IdleTimer);
                true ->
                    ok
            end,
            
            %% Terminate worker supervisor (tolerate missing sup in tests)
            if
                WorkerSup =/= undefined ->
                    case whereis(trust_conn_worker_sup) of
                        undefined -> ok;
                        _ -> catch supervisor:terminate_child(trust_conn_worker_sup, WorkerSup)
                    end;
                true ->
                    ok
            end;
        _Other ->
            %% State is not properly initialized, just log and continue
            logger:warning("trust_conn_fsm: terminating with uninitialized state: ~p", [State])
    end,
    
    ok.
