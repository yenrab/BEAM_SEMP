-module(semp_events).
-behaviour(gen_server).

-export([start_link/0, emit/3]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    {ok, #{}}.

emit(Name, Measurements, Metadata) ->
    %% thin shim over telemetry
    telemetry:execute(Name, Measurements, Metadata).

handle_call(_Req, _From, S) -> {reply, ok, S}.
handle_cast(_Msg, S) -> {noreply, S}.
handle_info(_Info, S) -> {noreply, S}.
terminate(_Reason, _State) -> ok.
code_change(_Old, S, _Extra) -> {ok, S}.
