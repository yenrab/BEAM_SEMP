%%%-------------------------------------------------------------------
%% @doc trust_rpc_worker - Worker process for handling RPC requests.
%% @end
%%%-------------------------------------------------------------------

-module(trust_rpc_worker).
-behaviour(gen_server).

-export([start_link/5]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(SERVER, ?MODULE).

%% Worker State
-record(state, {
    fsm_pid,  %% FSM process pid for sending responses
    req_id,
    request_type,
    mfa,
    args,
    socket,
    client_id,
    start_time
}).

%%--------------------------------------------------------------------
%% @doc
%% Starts the RPC worker for a specific request.
%% @end
%%--------------------------------------------------------------------
-spec start_link(pid(), term(), call | cast, {module(), atom(), integer()}, [term()]) ->
    {ok, pid()} | {error, term()}.
start_link(FsmPid, ReqId, Type, MFA, Args) ->
    gen_server:start_link(?MODULE, {FsmPid, ReqId, Type, MFA, Args}, []).

%%--------------------------------------------------------------------
%% @doc
%% Initializes the worker and executes the RPC.
%% @end
%%--------------------------------------------------------------------
-spec init({pid(), term(), call | cast, {module(), atom(), integer()}, [term()]}) ->
    {ok, #state{}} | {stop, term()}.
init({FsmPid, ReqId, Type, MFA, Args}) ->
    State = #state{
        fsm_pid = FsmPid,
        req_id = ReqId,
        request_type = Type,
        mfa = MFA,
        args = Args,
        start_time = erlang:monotonic_time()
    },
    
    %% Execute the RPC in the worker process
    case execute_rpc(State) of
        {ok, _Result} ->
            {ok, State};
        {error, Reason} ->
            {stop, Reason}
    end.

%%--------------------------------------------------------------------
%% @doc
%% Executes the RPC call or cast.
%% @end
%%--------------------------------------------------------------------
execute_rpc(State) ->
    #state{request_type = Type, mfa = {M, F, A}, args = Args, req_id = ReqId, fsm_pid = FsmPid} = State,
    
    %% Check if MFA is forbidden
    case semp_policy:is_forbidden(M, F, A) of
        true ->
            logger:warning("trust_rpc_worker: forbidden MFA ~p:~p/~p", [M, F, A]),
            {error, forbidden_mfa};
        false ->
            %% Check permissions (if client_id is available)
            case check_permissions(State) of
                ok ->
                    execute_mfa(Type, M, F, Args, ReqId, FsmPid);
                {error, Reason} ->
                    {error, Reason}
            end
    end.

%%--------------------------------------------------------------------
%% @doc
%% Checks permissions for the MFA.
%% @end
%%--------------------------------------------------------------------
check_permissions(State) ->
    #state{client_id = ClientId, mfa = {M, F, A}} = State,
    
    case ClientId of
        undefined ->
            {error, no_client_id};
        _ ->
            %% Check whitelist permissions
            case semp_whitelist:is_allowed(trust, ClientId) of
                true ->
                    %% Check specific MFA permissions
                    case check_mfa_permissions(ClientId, M, F, A) of
                        true -> ok;
                        false -> {error, permission_denied}
                    end;
                false ->
                    {error, not_whitelisted}
            end
    end.

%%--------------------------------------------------------------------
%% @doc
%% Checks specific MFA permissions.
%% @end
%%--------------------------------------------------------------------
check_mfa_permissions(ClientId, M, F, A) ->
    %% Use the same logic as trust_conn.erl perm_ok
    Tab = semp_whitelist:table(trust),
    case ets:lookup(Tab, ClientId) of
        [] -> false;
        [{_, any}] -> true;
        [{_, Spec}] -> mfa_in_spec(M, F, A, Spec);
        _ -> false
    end.

mfa_in_spec(M, F, A, Spec) when is_list(Spec) ->
    case lists:keyfind(M, 1, Spec) of
        false -> false;
        {M, any} -> true;
        {M, MFAs} when is_list(MFAs), MFAs =/= [] ->
            lists:member({F, A}, MFAs);
        _ -> false
    end;
mfa_in_spec(_, _, _, _) -> false.

%%--------------------------------------------------------------------
%% @doc
%% Executes the MFA and handles responses.
%% @end
%%--------------------------------------------------------------------
execute_mfa(Type, M, F, Args, ReqId, FsmPid) ->
    try
        case Type of
            call ->
                Result = apply(M, F, Args),
                send_response(ReqId, Result, FsmPid),
                telemetry:execute([trust, request, finish], 
                    #{duration_ms => calculate_duration_ms()}, 
                    #{req_id => ReqId, outcome => ok}),
                {ok, Result};
            cast ->
                apply(M, F, Args),
                telemetry:execute([trust, request, finish], 
                    #{duration_ms => calculate_duration_ms()}, 
                    #{req_id => ReqId, outcome => ok}),
                {ok, ok}
        end
    catch
        Class:Reason:_Stack ->
            logger:warning("trust_rpc_worker: RPC failed ~p:~p", [Class, Reason]),
            telemetry:execute([trust, worker, crash], #{}, 
                #{req_id => ReqId, class => Class, reason => Reason}),
            case Type of
                call ->
                    send_error(ReqId, Class, Reason, FsmPid);
                cast ->
                    ok
            end,
            {error, {Class, Reason}}
    end.

%%--------------------------------------------------------------------
%% @doc
%% Sends response back to client.
%% @end
%%--------------------------------------------------------------------
send_response(ReqId, Result, FsmPid) ->
    Frame = term_to_binary(#{t => result, req_id => ReqId, value => Result}),
    gen_statem:cast(FsmPid, {send_frame, Frame}).

%%--------------------------------------------------------------------
%% @doc
%% Sends error back to client.
%% @end
%%--------------------------------------------------------------------
send_error(ReqId, Class, Reason, FsmPid) ->
    Frame = term_to_binary(#{t => error, req_id => ReqId, kind => Class, reason => Reason}),
    gen_statem:cast(FsmPid, {send_frame, Frame}).

%%--------------------------------------------------------------------
%% @doc
%% Handles call messages.
%% @end
%%--------------------------------------------------------------------
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

%%--------------------------------------------------------------------
%% @doc
%% Handles cast messages.
%% @end
%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @doc
%% Handles info messages.
%% @end
%%--------------------------------------------------------------------
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @doc
%% Terminates the worker.
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @doc
%% Calculates duration in milliseconds since start_time.
%% @end
%%--------------------------------------------------------------------
calculate_duration_ms() ->
    %% TODO: Get start_time from state and calculate actual duration
    %% For now, return 0
    0.
