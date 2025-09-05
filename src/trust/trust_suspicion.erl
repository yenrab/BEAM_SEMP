-module(trust_suspicion).

-export([
    ensure/0,
    seed_from_whitelist/1,
    writePeer/1,
    bump/2, 
    is_trusted/1
]).

-define(TAB, trust_suspicions).


-doc "Purpose:\n"
     "Ensures that the ETS table used for trust state exists. Creates the table with concurrency\n"
     "options if it does not exist. Handles race conditions safely: if another process creates the\n"
     "table first, `ets:new/2` raises `badarg`, which is caught and ignored.\n"
     "\n"
     "Parameters:\n"
     "- None\n"
     "\n"
     "Return Value:\n"
     "- `ok` — whether the table already existed or was successfully created.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec ensure() -> ok.
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



-doc "Purpose:\n"
     "Seeds the suspicion table from a whitelist ETS table by clearing existing entries and "
     "streaming all fingerprints from the whitelist. Uses `ets:select/3` to iterate keys in "
     "chunks and delegates to `seed_stream/2` to perform batched inserts and return the total "
     "number of entries seeded.\n"
     "\n"
     "Parameters:\n"
     "- `WTab :: ets:tid() | atom()` — ETS table identifier or named table containing whitelist entries.\n"
     "\n"
     "Return Value:\n"
     "- `{ok, Count :: non_neg_integer()}` — total number of fingerprints seeded into the suspicion table.\n"
     "- `{error, whitelist_not_loaded}` — the provided whitelist table is undefined.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec seed_from_whitelist(ets:tid() | atom()) ->
          {ok, non_neg_integer()} | {error, whitelist_not_loaded}.
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
-doc "Purpose:\n"
     "Handles streaming results from `ets:select/3` to progressively seed the suspicion table. "
     "On each chunk, inserts `{FP, 0}` entries for all returned fingerprints and continues with "
     "the continuation until the end of table, returning the final count of inserted entries.\n"
     "\n"
     "Parameters:\n"
     "- `Sel :: '$end_of_table' | {Keys :: [binary()], Cont :: term()}` — streaming result from ETS select.\n"
     "- `Acc :: non_neg_integer()` — running count of inserted entries.\n"
     "\n"
     "Return Value:\n"
     "- `{ok, Total :: non_neg_integer()}` — total number of fingerprints inserted after streaming completes.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec seed_stream('$end_of_table' | {list(), term()}, non_neg_integer()) ->
          {ok, non_neg_integer()}.
seed_stream('$end_of_table', Acc) ->
    {ok, Acc};
seed_stream({Keys, Cont}, Acc) ->
    %% Insert {FP,0} for each key chunk
    ets:insert(?TAB, [{K, 0} || K <- Keys]),
    %% IMPORTANT: continue with ets:select/1 on the continuation
    seed_stream(ets:select(Cont), Acc + length(Keys)).




-doc "Purpose:\n"
     "Writes a peer fingerprint into the suspicion ETS table with an initial suspicion level of 0. "
     "Ensures the table exists before insertion.\n"
     "\n"
     "Parameters:\n"
     "- `FP :: binary()` — the peer fingerprint.\n"
     "\n"
     "Return Value:\n"
     "- `ok` — after successfully inserting the fingerprint with suspicion level 0.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec writePeer(binary()) -> ok.
writePeer(FP) ->
    ensure(),
    ets:insert(?TAB, {FP, 0}),
    ok.

%% -----------------------------------------------------------------------------
%% Suspicion tracking
%% -----------------------------------------------------------------------------


-doc "Purpose:\n"
     "Adjusts the suspicion level for a given peer fingerprint, either incrementing (`up`) or "
     "decrementing (`down`). If the suspicion count exceeds the configured limit, the peer is "
     "marked as `quarantined`. Ensures the suspicion table exists before updating.\n"
     "\n"
     "Parameters:\n"
     "- `FP :: binary()` — the peer fingerprint.\n"
     "- `Direction :: up | down` — direction of the suspicion adjustment.\n"
     "\n"
     "Return Value:\n"
     "- `unknown_peer` — the fingerprint is not present in the suspicion table.\n"
     "- `quarantined` — the fingerprint’s suspicion level exceeded the limit and is now quarantined.\n"
     "- `{ok, New :: non_neg_integer()}` — updated suspicion count for the fingerprint.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec bump(binary(), up | down) ->
          unknown_peer | quarantined | {ok, non_neg_integer()}.
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




-doc "Purpose:\n"
     "Determines whether a peer fingerprint is trusted by checking its status in the suspicion ETS table. "
     "If the fingerprint is not found, a warning is logged and the peer is considered untrusted. "
     "If present, the peer is trusted unless its status is explicitly `quarantined`.\n"
     "\n"
     "Parameters:\n"
     "- `FP :: binary()` — the peer fingerprint.\n"
     "\n"
     "Return Value:\n"
     "- `true` — if the fingerprint exists in the table and is not quarantined.\n"
     "- `false` — if the fingerprint is not found or has been quarantined.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec is_trusted(binary()) -> boolean().
is_trusted(FP) ->
    ensure(),
    case ets:lookup(?TAB, FP) of
        []        -> 
		    logger:warning("trust_suspicion: unable to find fp: ~p~nin table: ~p~n",[FP,?TAB]),
		    false;
        [{_, Val}] -> Val =/= quarantined
    end.
