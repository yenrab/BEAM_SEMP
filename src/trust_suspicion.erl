-module(trust_suspicion).

-export([
    writePeer/1,
    bump/2, 
    is_trusted/1
]).

-define(TAB, trust_permissions).

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
        []        -> false;
        [{_, Val}] -> Val =/= quarantined
    end.
