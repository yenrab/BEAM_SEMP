%%%-------------------------------------------------------------------
%% @doc trust_conn_worker_sup - Per-connection worker supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(trust_conn_worker_sup).
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

-define(SERVER, ?MODULE).

%%--------------------------------------------------------------------
%% @doc
%% Starts the per-connection worker supervisor.
%% @end
%%--------------------------------------------------------------------
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    supervisor:start_link(?MODULE, []).

%%--------------------------------------------------------------------
%% @doc
%% Initializes the worker supervisor with no initial children.
%% @end
%%--------------------------------------------------------------------
-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    %% DynamicSupervisor for temporary workers
    {ok, {#{strategy => one_for_one,
            intensity => 10,
            period => 5},
          []}}.

