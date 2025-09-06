-module(trust_listener).
-behaviour(gen_server).


%% @private
%% @doc
%% Purpose:
%% Implements the TRUST system listener as a gen_server. This module opens a
%% TLS listening socket, accepts incoming connections, and spawns dedicated
%% trust_conn processes to manage each secure client session.
%%
%% Main Responsibilities:
%% - Starting the listener process under a locally registered name.
%% - Initializing the TLS listening socket with secure defaults and configured certificates.
%% - Handling asynchronous `accept` messages to accept inbound TLS connections.
%% - Spawning trust_conn processes to manage the lifecycle of accepted connections.
%% - Retrying accepts on failure with a backoff delay.
%%
%% Author: Lee Barney
%% Version: 0.1
%% Last Modified: 2025-08-23
%%


-export([start_link/0]).
-export([init/1, handle_info/2, handle_call/3, handle_cast/2, terminate/2, code_change/3]).


-doc "Purpose:\n"
     "Starts the trust_listener gen_server under a locally registered name. This process "
     "manages listening for inbound TLS connections in the TRUST system.\n"
     "\n"
     "Parameters:\n"
     "- None\n"
     "\n"
     "Return Value:\n"
     "- `{ok, pid()}` — the gen_server was started successfully.\n"
     "- `{error, term()}` — the gen_server failed to start.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).



-doc "Purpose:\n"
     "Initializes the trust_listener server. If no whitelist configuration is available, logs a\n"
     "notice and returns an empty state. Otherwise, reads the configured port, builds TLS server\n"
     "options, attempts to bind a listening socket, schedules the first accept, and returns the\n"
     "initial state.\n"
     "\n"
     "Parameters:\n"
     "- `[]` — no arguments are expected.\n"
     "\n"
     "Return Value:\n"
     "- `{ok, #{lsock := ssl:sslsocket(), conns := map()}}` — listener started successfully.\n"
     "- `[]` — no whitelist found; running as a standalone node (no external connections).\n"
     "- `{stop, {listen_failed, eaddrinuse}}` — port is already in use.\n"
     "- `{stop, {listen_failed, Reason :: term()}}` — binding the listener failed for another reason.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-01\n".

-spec init([]) ->
          {ok, #{lsock := ssl:sslsocket(), conns := map()}}
        | []
        | {stop, {listen_failed, eaddrinuse}}
        | {stop, {listen_failed, term()}}.
init([]) ->
    semp_io:print_color([bold,red],"Using TRUST distribution.",[]),
    case semp_whitelist:whitelist_path(trust) of
            fail -> semp_io:print_color([bold,red],"No trust whitelist.config found. No TRUST connections will be accepted.",[]),
		    {ok, standalone, hibernate};
            _    -> logger:notice("Trust whitelist data file found in priv directory. Accepting external trust connections."),
		        io:format("trust whitelist file ~p~n",[semp_whitelist:whitelist_path(trust)]),
			WTableName = semp_whitelist:ensure(trust),%load the whitelist
			trust_suspicion:ensure(),%create the suspicion table
			trust_suspicion:seed_from_whitelist(WTableName),
			trust_token:ensure(),
		        %% 1) Read config from the correct app
    			Port = case application:get_env(trust, port) of
               				{ok, P} -> P;
               				undefined -> error({missing_env, {beam_semp, port}})
           			end,
    			TlsOpts = tls_server_opts(),
        		io:format("listener about to bind port ~p~n",[Port]),
    			%% 2) Try to bind (fail clearly on conflicts)
    			case ssl:listen(Port, [{reuseaddr, true} | TlsOpts]) of
        			{ok, LSock} ->
            				io:format("port: ~p~nopts: ~p~n",[Port,[{reuseaddr,true}|TlsOpts]]),
            				gen_server:cast(self() , accept),
            				semp_io:print_color([bold,red],"This is a TRUST client/server node.",[]),
        				{ok, #{lsock => LSock, conns => #{}}};
        			{error, eaddrinuse} ->
            				logger:error("trust_listener: port ~p is already in use", [Port]),
            				{stop, {listen_failed, eaddrinuse}};
        			{error, Reason} ->
            			logger:error("trust_listener: ssl:listen(~p, ...) failed: ~p", [Port, Reason]),
            			{stop, {listen_failed, Reason}}
    			end
    end.



-doc "Purpose:\n"
     "Builds the TLS server options for accepting incoming TRUST connections. Uses TLS 1.3, "
     "advertises the TRUST ALPN protocol, enforces peer certificate verification, and adds "
     "application-configured certificate options.\n"
     "\n"
     "Parameters:\n"
     "- None\n"
     "\n"
     "Return Value:\n"
     "- `[{atom(), term()}]` — list of TLS option tuples for use with ssl:listen/2.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec tls_server_opts() -> [{atom(), term()}].
tls_server_opts() ->
    Base = [
        {versions, ['tlsv1.3']},
        {alpn_preferred_protocols, [<<"trust/1">>]},
	{verify, verify_peer},
        {fail_if_no_peer_cert, true}
    ],
    Certs = application:get_env(trust, tls_opts, []),
    Base ++ Certs.




-doc "Purpose:\n"
     "Handles asynchronous cast messages for the listener server. On `accept`, performs a blocking "
     "transport accept, spawns a `trust_conn` process for the new socket, transfers ownership, and "
     "immediately schedules the next accept via `gen_server:cast/2`. On error, retries after a short "
     "delay using `timer:apply_after/4`. All other casts are ignored.\n"
     "\n"
     "Parameters:\n"
     "- `accept` — triggers the attempt to accept a new TLS connection.\n"
     "- `_` — any other cast message, which is ignored.\n"
     "- `St :: map()` — the server state containing the listening socket.\n"
     "\n"
     "Return Value:\n"
     "- `{noreply, NewState :: map()}` — updated server state after handling the cast.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec handle_cast(accept | term(), map()) -> {noreply, map()}.
%% accept loop (listener)
handle_cast(accept, #{lsock := LS, conns := Conns0} = St0) ->
    case ssl:transport_accept(LS, infinity) of
        {ok, Sock} ->
	    logger:debug("trust_listener: transport accepted on ~p~n",[LS]),
            %% spawn a runner that *waits* for the socket
            {Pid, MRef} = spawn_monitor(fun() ->
                receive
                    {handoff, S} -> trust_conn:start(S)
                after 30000 ->
                    exit(timeout_waiting_for_handoff)
                end
            end),

            %% transfer ownership before the child touches Sock
            case ssl:controlling_process(Sock, Pid) of
                ok ->
                    Peer = case ssl:peername(Sock) of {ok, P} -> P; _ -> undefined end,
                    Pid ! {handoff, Sock},
                    Conns = Conns0#{ MRef => #{pid => Pid,
                                                peer => Peer,
                                                started_at => erlang:monotonic_time()} },
                    gen_server:cast(self(), accept),
                    {noreply, St0#{conns := Conns}};
                {error, closed} ->
                    %% child may have died, socket already closed; clean up
                    demonitor(MRef, [flush]),
                    gen_server:cast(self(), accept),
                    {noreply, St0};
                {error, Reason} ->
                    demonitor(MRef, [flush]),
                    logger:warning("controlling_process failed: ~p", [Reason]),
                    gen_server:cast(self(), accept),
                    {noreply, St0}
            end;

        {error, _} ->
            _Ref = timer:apply_after(200, gen_server, cast, [self(), accept]),
            {noreply, St0}
    end;
handle_cast(_, St) ->
	io:format("handle cast: any"),
    {noreply, St}.


handle_call(_Req, _From, St) -> 
    {reply, ok, St}.



%% Log the DOWN; keep the listener alive
handle_info({'DOWN', MRef, process, Pid, Reason}, #{conns := Conns0} = St0) ->
    Meta = maps:get(MRef, Conns0, #{}),
    Peer = maps:get(peer, Meta, undefined),
    DurMs = case maps:get(started_at, Meta, undefined) of
                T when is_integer(T) ->
                     erlang:convert_time_unit(erlang:monotonic_time() - T, native, millisecond);
		_ -> undefined
            end,
    case Reason of
        normal ->
            %% Usually an orderly close; log at debug or ignore
            logger:debug("trust_conn ~p (~p) closed normally (~p ms)", [Pid, Peer, DurMs]);
        shutdown ->
            logger:notice("trust_conn ~p (~p) shutdown (~p ms)", [Pid, Peer, DurMs]);
        _ ->
            logger:warning("trust_conn ~p (~p) DOWN: ~p (~p ms)", [Pid, Peer, Reason, DurMs])
    end,
    {noreply, St0#{conns := maps:remove(MRef, Conns0)}};

handle_info(_, St) ->
    {noreply, St}.

terminate(_Reason, _State) -> ok.
code_change(_Old, State, _Extra) -> {ok, State}.
