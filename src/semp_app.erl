%%%-------------------------------------------------------------------
%% @doc semp public API
%% @end
%%%-------------------------------------------------------------------

-module(semp_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    %% Disable distribution ASAP (idempotent).
    semp_kill_it_all:std_distribution(),
    %% Merge api module names and function names into the atom table
    trpc_loader:load_api(),
    semp_sup:start_link().

stop(_State) ->
    ok.

%% internal functions
