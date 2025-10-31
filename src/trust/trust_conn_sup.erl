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
%% Initializes the trust_conn_sup supervisor with trust_conn_worker_sup as an initial child.
%% This supervisor manages the worker supervisor and dynamic trust connection FSM processes
%% that are started on-demand when TLS connections are accepted.
%% @end
%%--------------------------------------------------------------------
-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    %% Worker supervisor as initial permanent child
    WorkerSup = {trust_conn_worker_sup, 
                 {trust_conn_worker_sup, start_link, []}, 
                 permanent, 
                 5000, 
                 supervisor, 
                 [trust_conn_worker_sup]},
    %% DynamicSupervisor with one_for_one strategy
    %% Worker supervisor starts first, then FSMs are added dynamically
    {ok, {#{strategy => one_for_one,
            intensity => 50,
            period => 10},
          [WorkerSup]}}.


