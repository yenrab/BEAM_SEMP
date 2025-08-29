-module(trust_listener_sup).
-behaviour(supervisor).
%% @private
%% @doc
%% Purpose:
%% Implements the supervisor for the TRUST system listener. This supervisor
%% manages the lifecycle of the trust_listener, ensuring that the
%% TLS listener is always running and automatically restarted if it fails.
%%
%% Main Responsibilities:
%% - Starting and supervising the trust_listener process.
%% - Defining restart strategy, shutdown parameters, and child specifications.
%% - Ensuring high availability of the TLS listener by restarting it on failure.
%%
%% Author: Lee Barney
%% Version: 0.1
%% Last Modified: 2025-08-23
%%
%%

-export([start_link/0, init/1]).

-doc "Purpose:\n"
     "Starts the trust_listener_sup supervisor under a locally registered name. "
     "This supervisor manages the trust_listener gen_server responsible for "
     "accepting inbound TLS connections.\n"
     "\n"
     "Parameters:\n"
     "- None\n"
     "\n"
     "Return Value:\n"
     "- `{ok, pid()}` — the supervisor was started successfully.\n"
     "- `{error, term()}` — the supervisor failed to start.\n"
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
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).




-doc "Purpose:\n"
     "Initializes the trust_listener_sup supervisor by defining the child specification "
     "for the trust_listener gen_server. Ensures the listener process is supervised as "
     "a permanent worker with restart and shutdown parameters.\n"
     "\n"
     "Parameters:\n"
     "- `[]` — no arguments are expected.\n"
     "\n"
     "Return Value:\n"
     "- `{ok, {SupFlags, [ChildSpec]}}` — the supervisor initialization result, including "
     "flags and the trust_listener child specification.\n"
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

-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}} | {stop, term()}.
init([]) ->
    Listener = {trust_listener, {trust_listener, start_link, []}, permanent, 5000, worker, [trust_listener]},
    {ok, {{one_for_one, 5, 10}, [Listener]}}.
