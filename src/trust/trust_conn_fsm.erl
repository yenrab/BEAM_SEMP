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
-spec start_link(ssl:sslsocket(), map(), map()) -> {ok, pid()} | {error, term()}.
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
-spec init({ssl:sslsocket(), map(), map()}) -> {ok, ?HANDSHAKE_TOKEN, #state{}}.
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
    ssl:setopts(Socket, [{active, once}]),
    
    {ok, ?HANDSHAKE_TOKEN, State}.

%%--------------------------------------------------------------------
%% @doc
%% Extracts client ID from TLS certificate.
%% @end
%%--------------------------------------------------------------------
extract_client_id(Socket) ->
    case ssl:peercert(Socket) of
        {ok, CertDer} ->
            %% Generate fingerprint from certificate
            semp_util:cert_fingerprint_sha512(CertDer);
        {error, _Reason} ->
            undefined
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
    handle_client_cancel(State);

handle_event({ssl_error, Socket, Reason}, _StateName, State, _Data) ->
    handle_ssl_error(Reason, State);

handle_event(cast, {send_frame, Frame}, StateName, State) 
    when StateName =:= ?ACTIVE; StateName =:= ?DRAINING ->
    semp_util:send_frame(State#state.socket, Frame),
    {keep_state, State};

handle_event(Event, StateName, State, _Data) ->
    logger:warning("trust_conn_fsm: unhandled event ~p in state ~p", [Event, StateName]),
    {keep_state, State}.

%%--------------------------------------------------------------------
%% @doc
%% Handles handshake and token validation.
%% @end
%%--------------------------------------------------------------------
handle_handshake_token(Socket, Bin, State) ->
    case safe_term(Bin) of
        #{t := token_present, token := Token} ->
            case validate_token(Token, State) of
                ok ->
                    transition_to_active(State);
                {error, _Reason} ->
                    send_goaway(deny, 0, Socket),
                    ssl:close(Socket),
                    {next_state, ?CLOSING, State}
            end;
        #{t := token_issue, token := Token} ->
            case issue_token(Token, State) of
                ok ->
                    transition_to_active(State);
                {error, _Reason} ->
                    send_goaway(deny, 0, Socket),
                    ssl:close(Socket),
                    {next_state, ?CLOSING, State}
            end;
        _Other ->
            send_goaway(protocol, 0, Socket),
            ssl:close(Socket),
            {next_state, ?CLOSING, State}
    end.

%%--------------------------------------------------------------------
%% @doc
%% Handles active state requests with backpressure.
%% @end
%%--------------------------------------------------------------------
handle_active_request(Socket, Bin, State) ->
    #state{inflight = Inflight, session_config = Config, client_id = ClientId} = State,
    
    %% Validate frame size
    case byte_size(Bin) of
        Size when Size > ?FRAME_SIZE_MAX ->
            trust_suspicion:bump(ClientId, up),
            send_goaway(protocol, 0, Socket),
            ssl:close(Socket),
            {next_state, ?CLOSING, State};
        _ ->
            if
                Inflight < Config#session_config.max_inflight ->
                    case decode_request(Bin) of
                        {ok, Request} ->
                            case spawn_worker(Request, State) of
                                {ok, NewState} ->
                                    ssl:setopts(Socket, [{active, once}]),
                                    {next_state, ?ACTIVE, NewState, [{state_timeout, Config#session_config.idle_ms, idle}]};
                                {error, duplicate} ->
                                    ssl:setopts(Socket, [{active, once}]),
                                    {next_state, ?ACTIVE, State, [{state_timeout, Config#session_config.idle_ms, idle}]};
                                {error, _Reason} ->
                                    send_goaway(protocol, 0, Socket),
                                    ssl:close(Socket),
                                    {next_state, ?CLOSING, State}
                            end;
                        {error, Reason} ->
                            trust_suspicion:bump(ClientId, up),
                            send_goaway(protocol, 0, Socket),
                            ssl:close(Socket),
                            {next_state, ?CLOSING, State}
                    end;
                true ->
                    %% Backpressure: pause reads
                    telemetry:execute([trust, request, refuse], #{}, 
                        #{reason => max_inflight}),
                    telemetry:execute([trust, pause], #{}, #{}),
                    ssl:setopts(Socket, [{active, false}]),
                    {next_state, ?ACTIVE, State}
            end
    end.

%%--------------------------------------------------------------------
%% @doc
%% Handles requests during draining phase.
%% @end
%%--------------------------------------------------------------------
handle_draining_request(Socket, Bin, State) ->
    %% Ignore new requests during draining
    ssl:setopts(Socket, [{active, once}]),
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
    
    %% Log worker completion
    logger:debug("trust_conn_fsm: worker ~p completed for client ~p, inflight: ~p", [Pid, ClientId, NewInflight]),
    
    %% Resume reads if we were paused and now have capacity
    if
        NewInflight < Config#session_config.max_inflight ->
            telemetry:execute([trust, resume], #{}, #{}),
            ssl:setopts(Socket, [{active, once}]);
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
    #state{inflight = Inflight, socket = Socket} = State,
    
    NewInflight = Inflight - 1,
    NewState = State#state{inflight = NewInflight},
    
    if
        NewInflight =:= 0 ->
            ssl:close(Socket),
            {next_state, ?CLOSING, NewState};
        true ->
            {next_state, ?DRAINING, NewState}
    end.


%%--------------------------------------------------------------------
%% @doc
%% Handles client cancellation.
%% @end
%%--------------------------------------------------------------------
handle_client_cancel(State) ->
    #state{worker_sup = WorkerSup} = State,
    
    %% Kill all workers immediately
    if
        WorkerSup =/= undefined ->
            supervisor:terminate_child(trust_conn_worker_sup, WorkerSup);
        true ->
            ok
    end,
    
    {next_state, ?CLOSING, State}.

%%--------------------------------------------------------------------
%% @doc
%% Handles SSL errors.
%% @end
%%--------------------------------------------------------------------
handle_ssl_error(Reason, State) ->
    logger:warning("trust_conn_fsm: SSL error ~p", [Reason]),
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
    
    %% Start worker supervisor
    {ok, WorkerSup} = trust_conn_worker_sup:start_link(),
    
    NewState = State#state{
        max_age_timer = MaxAgeTimer,
        worker_sup = WorkerSup
    },
    
    %% Emit telemetry for session start
    telemetry:execute([trust, session, start], #{}, 
        #{client_id => ClientId, peer_info => PeerInfo}),
    
    %% Log session start
    logger:info("trust_conn_fsm: session started for client ~p", [ClientId]),
    
    ssl:setopts(Socket, [{active, once}]),
    {next_state, ?ACTIVE, NewState, [{state_timeout, Config#session_config.idle_ms, idle}]}.

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
%% Handles drain timeout.
%% @end
%%--------------------------------------------------------------------
handle_drain_timeout(State) ->
    #state{socket = Socket, client_id = ClientId} = State,
    logger:info("trust_conn_fsm: drain timeout for client ~p", [ClientId]),
    ssl:close(Socket),
    {next_state, ?CLOSING, State}.

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
    case trust_token:validate(Token, ClientId) of
        ok -> ok;
        {error, _Reason} -> {error, invalid_token}
    end.

%%--------------------------------------------------------------------
%% @doc
%% Issues new token to client.
%% @end
%%--------------------------------------------------------------------
issue_token(Token, State) ->
    #state{client_id = ClientId, socket = Socket} = State,
    case trust_token:issue(ClientId) of
        {ok, NewToken} ->
            %% Send token to client
            Frame = term_to_binary(#{t => token_issue, token => NewToken}),
            case semp_util:send_frame(Socket, Frame) of
                ok -> ok;
                {error, _Reason} -> {error, send_failed}
            end;
        {error, _Reason} ->
            {error, token_issue_failed}
    end.

%%--------------------------------------------------------------------
%% @doc
%% Decodes request frame.
%% @end
%%--------------------------------------------------------------------
decode_request(Bin) ->
    case safe_term(Bin) of
        #{t := call, req_id := ReqId, m := M, f := F, a := A, args := Args} ->
            {ok, {call, ReqId, M, F, A, Args}};
        #{t := cast, req_id := ReqId, m := M, f := F, a := A, args := Args} ->
            {ok, {cast, ReqId, M, F, A, Args}};
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
                        start => {trust_rpc_worker, start_link, [self(), ReqId, call, {M, F, A}, Args]},
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
                            logger:error("trust_conn_fsm: failed to start worker: ~p", [Reason]),
                            {error, worker_start_failed}
                    end;
                {cast, ReqId, M, F, A, Args} ->
                    WorkerSpec = #{
                        id => {trust_rpc_worker, ReqId},
                        start => {trust_rpc_worker, start_link, [self(), ReqId, cast, {M, F, A}, Args]},
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
                            logger:error("trust_conn_fsm: failed to start worker: ~p", [Reason]),
                            {error, worker_start_failed}
                    end
            end
    end.

%%--------------------------------------------------------------------
%% @doc
%% Terminates the FSM.
%% @end
%%--------------------------------------------------------------------
terminate(Reason, _StateName, State) ->
    #state{max_age_timer = Timer, worker_sup = WorkerSup, client_id = ClientId} = State,
    
    %% Emit telemetry for session end
    telemetry:execute([trust, session, 'end'], 
        #{age_ms => 0},  %% TODO: calculate actual age
        #{reason => Reason, client_id => ClientId}),
    
    %% Cancel max-age timer
    if
        Timer =/= undefined ->
            erlang:cancel_timer(Timer);
        true ->
            ok
    end,
    
    %% Terminate worker supervisor
    if
        WorkerSup =/= undefined ->
            supervisor:terminate_child(trust_conn_worker_sup, WorkerSup);
        true ->
            ok
    end,
    
    ok.
