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
     "Initializes the trust_listener gen_server by retrieving the configured port, building "
     "TLS server options, and starting a listening socket. Schedules the first accept "
     "operation by sending an internal message to itself.\n"
     "\n"
     "Parameters:\n"
     "- `[]` — no arguments are expected.\n"
     "\n"
     "Return Value:\n"
     "- `{ok, State :: map()}` — the initial state containing the listening socket.\n"
     "- `{stop, Reason}` — initialization failed.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec init([]) -> {ok, map()} | {stop, term()}.
init([]) ->
    {ok, Port} = application:get_env(trust, port),
    TlsOpts = tls_server_opts(),
    io:format("port: ~p~nopts: ~p~n",[Port,TlsOpts]),
    {ok, LSock} = ssl:listen(Port, TlsOpts),
    gen_server:cast(self(), accept),
    {ok, LSock}.



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
handle_cast(accept, ListeningSocket) ->
    case ssl:transport_accept(ListeningSocket, infinity) of
        {ok, Sock} ->
            Pid = spawn_link(trust_conn, start, [Sock]),
            ok = ssl:controlling_process(Sock, Pid),
            gen_server:cast(self(), accept),   % schedule next accept immediately
            {noreply, ListeningSocket};
        {error, _} ->
            %% retry after a short delay (send a *cast*, not a raw message)
            _Ref = timer:apply_after(200, gen_server, cast, [self(), accept]),
            {noreply, ListeningSocket}
    end;
handle_cast(_, ListeningSocket) ->
    {noreply, ListeningSocket}.



handle_call(_Req, _From, St) -> 
    {reply, ok, St}.
handle_info(_Msg, St) ->
    {noreply, St}.

terminate(_Reason, _State) -> ok.
code_change(_Old, State, _Extra) -> {ok, State}.
