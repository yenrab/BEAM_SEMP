-module(trust_suspicion).

-export([
    ensure/0,
    seed_from_whitelist/1,
    writePeer/1,
    bump/2, 
    is_trusted/1
]).

-define(TAB, trust_suspicions).

ensure() ->
    case ets:info(?TAB) of
        undefined ->
            %% Race-safe create: if another process wins, ets:new throws badarg — we swallow it.
            try
                ets:new(?TAB, [named_table, set, public,
                               {read_concurrency, true},
                               {write_concurrency, true}])
            catch
                error:badarg -> ok
            end,
            ok;
        _ ->
            ok
    end.

%% Clobber suspicion table and seed from WTab (an ETS table name or tid)
seed_from_whitelist(WTab) ->
    ensure(),
    case ets:info(WTab) of
        undefined ->
            {error, whitelist_not_loaded};
        _ ->
            %% 1) Clear suspicion table
            ets:delete_all_objects(?TAB),
            %% 2) Stream all keys from whitelist: entries are {FP, Spec}
            MS = [{{'$1','_'}, [], ['$1']}],
            seed_stream(ets:select(WTab, MS, 512), 0)
    end.

%% Handle the streaming result from ets:select/3
seed_stream('$end_of_table', Acc) ->
    {ok, Acc};
seed_stream({Keys, Cont}, Acc) ->
    %% Insert {FP,0} for each key chunk
    ets:insert(?TAB, [{K, 0} || K <- Keys]),
    %% IMPORTANT: continue with ets:select/1 on the continuation
    seed_stream(ets:select(Cont), Acc + length(Keys)).


writePeer(FP) ->
    ensure(),
    ets:insert(?TAB, {FP, 0}),
    ok.

%% -----------------------------------------------------------------------------
%% Suspicion tracking
%% -----------------------------------------------------------------------------
bump(FP, Direction) ->
    ensure(),
    Limit = application:get_env(semp, suspicion_limit, 3),
    case ets:lookup(?TAB, FP) of
        [] ->
            unknown_peer;

        [{FP, quarantined}] ->
            quarantined;

        [{FP, _Count}] when Direction =:= up ->
            %% +1, floor at 0 (no-op here but keeps symmetry)
            New = ets:update_counter(?TAB, FP, {2, +1, 0, 0}),
            if
                New > Limit ->
                    true = ets:insert(?TAB, {FP, quarantined}),
                    quarantined;
                true ->
                    {ok, New}
            end;

        [{FP, _Count}] when Direction =:= down ->
            %% -1 with floor at 0
            New = ets:update_counter(?TAB, FP, {2, -1, 0, 0}),
            {ok, New}
    end.


is_trusted(FP) ->
    ensure(),
    case ets:lookup(?TAB, FP) of
        []        -> 
		    logger:warning("trust_suspicion: unable to find fp: ~p~nin table: ~p~n",[FP,?TAB]),
		    false;
        [{_, Val}] -> Val =/= quarantined
    end.
