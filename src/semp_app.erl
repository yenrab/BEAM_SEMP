%%%-------------------------------------------------------------------
%% @doc semp public API
%% @end
%%%-------------------------------------------------------------------

-module(semp_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    semp_sup:start_link().

stop(_State) ->
    ok.

%% internal functions
