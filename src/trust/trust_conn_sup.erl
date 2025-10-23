%%%-------------------------------------------------------------------
%% @doc trust_conn_sup - DynamicSupervisor for managing trust connections.
%% @end
%%%-------------------------------------------------------------------

-module(trust_conn_sup).
-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

-define(SERVER, ?MODULE).

%%--------------------------------------------------------------------
%% @doc
%% Starts the trust_conn_sup DynamicSupervisor.
%% @end
%%--------------------------------------------------------------------
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%--------------------------------------------------------------------
%% @doc
%% Initializes the trust_conn_sup DynamicSupervisor with no initial children.
%% This supervisor manages dynamic trust connection FSM processes that are
%% started on-demand when TLS connections are accepted.
%% @end
%%--------------------------------------------------------------------
-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    %% DynamicSupervisor with one_for_one strategy
    %% No initial children - all children are added dynamically
    {ok, {#{strategy => one_for_one,
            intensity => 50,
            period => 10},
          []}}.


