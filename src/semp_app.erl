%%%-------------------------------------------------------------------
%% @doc semp public API
%% @end
%%%-------------------------------------------------------------------

-module(semp_app).

-behaviour(application).

-export([start/2, stop/1]).
-doc "Purpose:\n"
     "Application entry point for starting the SEMP system. Disables Erlang distribution immediately, "
     "loads API modules and functions into the atom table, and starts the top-level supervisor.\n"
     "\n"
     "Parameters:\n"
     "- `_StartType :: term()` — standard OTP application start type (ignored).\n"
     "- `_StartArgs :: term()` — application start arguments (ignored).\n"
     "\n"
     "Return Value:\n"
     "- `{ok, Pid :: pid()}` — PID of the top-level supervisor on success.\n"
     "- `{error, Reason :: term()}` — if the supervisor failed to start.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-05\n".

-spec start(term(), term()) -> {ok, pid()} | {error, term()}.
start(_StartType, _StartArgs) ->
    %% Disable distribution ASAP (idempotent).
    semp_kill_it_all:std_distribution(),
    %% Merge api module names and function names into the atom table
    trpc_loader:load_api(),
    semp_sup:start_link().

stop(_State) ->
    ok.

%% internal functions
