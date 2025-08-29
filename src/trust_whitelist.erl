%% src/trust_whitelist.erl
-module(trust_whitelist).

-export([ensure/0, is_allowed/1, reload/0]).

-define(TAB, trust_whitelist).
-define(WHITELIST_FILE, "whitelist.config").
-define(CERTS_DIR,"certs").

-doc "Purpose:\n"
     "Ensures that the ETS table for the whitelist exists. If the table does not exist, "
     "creates it with concurrency options and populates it from the priv directory. "
     "If it already exists, no action is taken.\n"
     "\n"
     "Parameters:\n"
     "- None\n"
     "\n"
     "Return Value:\n"
     "- `ok` — if the whitelist table already exists or was created successfully.\n"
     "- `Result :: term()` — the return value from load_from_priv/0 when the table is newly created.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec ensure() -> ok | term().
ensure() ->
    case ets:info(?TAB) of
        undefined ->
            _ = ets:new(?TAB, [named_table, set, protected, {read_concurrency, true}]),
            load_from_priv();
        _ ->
            ok
    end.




-doc "Purpose:\n"
     "Determines whether a given fingerprint is present in the whitelist. Ensures the ETS table "
     "exists before performing the lookup.\n"
     "\n"
     "Parameters:\n"
     "- `FP :: binary()` — the certificate fingerprint to check.\n"
     "\n"
     "Return Value:\n"
     "- `true` — if the fingerprint is found in the whitelist.\n"
     "- `false` — if the fingerprint is not found in the whitelist.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec is_allowed(binary()) -> boolean().
is_allowed(FP) when is_binary(FP) ->
    ensure(),
    case ets:lookup(?TAB, FP) of
        [{_, _Spec}] -> true;
        _ -> false
    end.


-doc "Purpose:\n"
     "Reloads the whitelist ETS table. Ensures the table exists, removes all current entries, "
     "and repopulates it with data from the priv directory.\n"
     "\n"
     "Parameters:\n"
     "- None\n"
     "\n"
     "Return Value:\n"
     "- `Result :: term()` — the return value of load_from_priv/0 after repopulating the table.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec reload() -> term().
reload() ->
    ensure(),
    ets:delete_all_objects(?TAB),
    load_from_priv().

%% --- helper functions  ------------------------------
-doc "Purpose:\n"
     "Loads whitelist entries from the application's priv directory. If the priv directory "
     "is unavailable, logs a warning and behaves as an independent node by rejecting all peers. "
     "If the whitelist file exists and contains a map, its entries are loaded into the ETS table. "
     "If the file is missing or invalid, returns `fail` to indicate that no whitelist entries "
     "were loaded.\n"
     "\n"
     "Parameters:\n"
     "- None\n"
     "\n"
     "Return Value:\n"
     "- `ok` — whitelist entries successfully loaded.\n"
     "- `fail` — the whitelist file was missing or invalid.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec load_from_priv() -> ok | fail.
load_from_priv() ->
    case whitelist_path() of
        fail ->
            %% No priv dir available -> behave as independent node (reject all).
            logger:warning("whitelist.config not found. Running as independent node."),
            ok;
        Path ->
            case file:consult(Path) of
                {ok, [Map]} when is_map(Map) ->
                    load_spec_map(Map), ok;
                _ ->
                    %% Missing/invalid file -> empty whitelist
                    fail
            end
    end.



-doc "Purpose:\n"
     "Resolves the filesystem path of the whitelist configuration file. If the application's "
     "priv directory is available, constructs the full path to the whitelist file. If the "
     "priv directory cannot be resolved, returns `fail`.\n"
     "\n"
     "Parameters:\n"
     "- None\n"
     "\n"
     "Return Value:\n"
     "- `Path :: string()` — the resolved whitelist file path.\n"
     "- `fail` — no priv directory or whitelist.config is available.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec whitelist_path() -> string() | fail.
whitelist_path() ->
    case code:priv_dir(semp) of
        Dir when is_list(Dir) -> filename:join(Dir, ?WHITELIST_FILE);
        {error, _}            -> fail 
    end.

-doc "Purpose:\n"
     "Loads whitelist specifications from a map into the ETS table. Iterates over all "
     "entries and inserts each fingerprint specification.\n"
     "\n"
     "Parameters:\n"
     "- `Map :: map()` — certificate fingerprint specifications keyed by fingerprint.\n"
     "\n"
     "Return Value:\n"
     "- `ok` — after all entries have been inserted.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec load_spec_map(map()) -> ok.
load_spec_map(Map) ->
    maps:fold(fun insert_entry/3, ok, Map).




-doc "Purpose:\n"
     "Inserts a whitelist entry into the ETS table from a certificate file. Reads the certificate, "
     "computes its fingerprint, normalizes the associated specification, and stores the entry if valid. "
     "If the certificate cannot be read or the specification is invalid, the entry is skipped.\n"
     "\n"
     "Parameters:\n"
     "- `FileName :: string()` — the certificate file name.\n"
     "- `Val0 :: term()` — the raw whitelist specification value.\n"
     "- `Acc :: term()` — accumulator value, typically `ok`, returned unchanged.\n"
     "\n"
     "Return Value:\n"
     "- `Acc :: term()` — the accumulator, unchanged.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec insert_entry(string(), term(), term()) -> term().
insert_entry(FileName, Val0, Acc) ->
    CertPath = cert_path(FileName),
    case read_cert_fp(CertPath) of
        {ok, FP} ->
            case normalize_value(Val0) of
                invalid -> Acc;
                Spec    -> ets:insert(?TAB, {FP, Spec}), Acc
            end;
        {error, Reason} ->
            logger:warning("whitelist: skipping ~ts (~p)", [CertPath, Reason]),
            Acc
    end.



-doc "Purpose:\n"
     "Builds the filesystem path to a certificate file located in the application's priv directory. "
     "Accepts the filename as a binary, list, or atom and normalizes it to a string. If the priv "
     "directory cannot be resolved, returns `fail`.\n"
     "\n"
     "Parameters:\n"
     "- `FileName :: binary() | string() | atom()` — the certificate file name.\n"
     "\n"
     "Return Value:\n"
     "- `Path :: string()` — the resolved certificate path.\n"
     "- `fail` — if the priv directory is unavailable.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec cert_path(binary() | string() | atom()) -> string() | fail.
cert_path(FileName) ->
    Name =
        case FileName of
            B when is_binary(B) -> binary_to_list(B);
            L when is_list(L)   -> L;
            A when is_atom(A)   -> atom_to_list(A)
        end,
    case code:priv_dir(semp) of
        Dir when is_list(Dir) -> filename:join([Dir, ?CERTS_DIR, Name]);
        {error, _}            -> fail
    end.

-doc "Purpose:\n"
     "Reads a certificate file and extracts its SHA-512 SPKI fingerprint. Supports both PEM-encoded "
     "and raw DER-encoded certificates.\n"
     "\n"
     "Parameters:\n"
     "- `Path :: string()` — the filesystem path to the certificate file.\n"
     "\n"
     "Return Value:\n"
     "- `{ok, FP :: binary()}` — the computed SPKI fingerprint of the certificate.\n"
     "- `{error, Reason :: term()}` — if the file could not be read or parsed.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec read_cert_fp(string()) -> {ok, binary()} | {error, term()}.
read_cert_fp(Path) ->
    case file:read_file(Path) of
        {ok, Bin} ->
            Dec = public_key:pem_decode(Bin),
            case lists:dropwhile(fun({T,_,_}) -> T =/= 'Certificate' end, Dec) of
                [{'Certificate', Der, _} | _] ->
                    {ok, semp_util:spki_fingerprint_sha512(Der)};
                [] ->
                    %% maybe raw DER:
                    {ok, semp_util:spki_fingerprint_sha512(Bin)}
            end;
        {error, Reason} ->
            {error, Reason}
    end.



-doc "Purpose:\n"
     "Normalizes a whitelist specification value into a canonical form. Accepts `any` or a list\n"
     "of entries mapping a module to either `any` or a list of {Function, Arity} pairs. Module-level\n"
     "`any` overrides any function lists for that module. Invalid modules, malformed entries, and\n"
     "empty lists are ignored. Returns `invalid` if no valid entries remain.\n"
     "\n"
     "Parameters:\n"
     "- `any` — indicates unrestricted permissions for the module(s) provided.\n"
     "- `List :: list()` — entries of the form `{Module, any}` or `{Module, [{Function, Arity}, ...]}`.\n"
     "- `_ :: term()` — any other input, treated as invalid.\n"
     "\n"
     "Return Value:\n"
     "- `any` — when the input is exactly `any`.\n"
     "- `Canon :: [{module(), any | [{atom(), non_neg_integer()}]}]` — normalized specification list.\n"
     "- `invalid` — when the input is empty or contains no valid entries after normalization.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec normalize_value(any | list() | term()) ->
          any
        | [{module(), any | [{atom(), non_neg_integer()}]}]
        | invalid.
normalize_value(any) -> any;
normalize_value(List) when is_list(List) ->
    %% Build a map Mod => any | [{Fun,Arity},...]
    Acc =
        lists:foldl(
          fun
              ({ModuleName, any}, Accum) ->
                  case to_atom(ModuleName) of
                      invalid -> Accum;
                      Mod     -> maps:put(Mod, any, Accum)  %% module-level any overrides lists
                  end;
              ({ModuleName, FunctionsWithAritys}, Accum) when is_list(FunctionsWithAritys) ->
                  case to_atom(ModuleName) of
                      invalid -> Accum;
                      Mod ->
                          FunctionsWithAritys = normalize_funlist(FunctionsWithAritys),
                          case FunctionsWithAritys of
                              [] -> Accum;  %% skip empty lists
                              _  ->
                                  case maps:get(Mod, Accum, undefined) of
                                      any               -> Accum;                       %% any already set; keep it
                                      undefined         -> maps:put(Mod, FunctionsWithAritys, Accum);
                                      Prev when is_list(Prev) ->
                                          maps:put(Mod, uniq_pairs(Prev ++ FunctionsWithAritys), Accum)
                                  end
                          end
                  end;
              (_, Accum) -> Accum
          end, #{}, List),
    case maps:size(Acc) of
        0 -> invalid;
        _ ->
            %% Canonical form: [{Module, any} | {Module, [{Fun,Arity},...]}]
            Mods = maps:keys(Acc),
            [ case maps:get(M, Acc) of any -> {M, any}; FunctionsWithAritys -> {M, FunctionsWithAritys} end
              || M <- Mods ]
    end;
normalize_value(_) -> invalid.



-doc "Purpose:\n"
     "Normalizes a list of function/arity entries into a canonical list of {Function, Arity} "
     "pairs. Invalid entries are skipped, names are atomized when valid, and duplicates are "
     "removed with a deterministic order.\n"
     "\n"
     "Parameters:\n"
     "- `L :: list()` — list of entries, each expected as `{Function, Arity}` with non-negative integer arity.\n"
     "\n"
     "Return Value:\n"
     "- `[{atom(), non_neg_integer()}]` — normalized, de-duplicated list of function/arity pairs.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n log n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec normalize_funlist(list() | term()) -> [{atom(), non_neg_integer()}].
normalize_funlist(L) when is_list(L) ->
    Norm =
        [ case E of
              {F0, A} when is_integer(A), A >= 0 ->
                  case to_atom(F0) of
                      invalid -> skip;
                      F       -> {F, A}
                  end;
              _ -> skip
          end
        || E <- L ],
    [X || X <- lists:usort(Norm), X =/= skip];
normalize_funlist(_) -> [].


-doc "Purpose:\n"
     "Removes duplicate function/arity pairs from a list by sorting and returning a unique set.\n"
     "\n"
     "Parameters:\n"
     "- `L :: list()` — list of elements to deduplicate.\n"
     "\n"
     "Return Value:\n"
     "- `Unique :: list()` — sorted list of unique elements.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n log n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec uniq_pairs(list()) -> list().
uniq_pairs(L) ->
    lists:usort(L).



-doc "Purpose:\n"
     "Converts the given value into an atom if possible. Supports atoms, binaries, and strings (lists). "
     "Invalid or empty values return the atom `invalid`.\n"
     "\n"
     "Parameters:\n"
     "- `A :: atom()` — returned unchanged.\n"
     "- `B :: binary()` — converted to an atom using UTF-8; returns `invalid` if conversion fails.\n"
     "- `S :: string()` — converted to an atom; returns `invalid` if conversion fails.\n"
     "- `_ :: term()` — any unsupported or empty value, results in `invalid`.\n"
     "\n"
     "Return Value:\n"
     "- `atom()` — the converted atom.\n"
     "- `invalid` — indicates conversion failure.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec to_atom(atom() | binary() | string() | term()) -> atom() | invalid.
to_atom(A) when is_atom(A) -> A;
to_atom(B) when is_binary(B), B =/= <<>> ->
    try binary_to_atom(B, utf8) catch _:_ -> invalid end;
to_atom(S) when is_list(S), S =/= [] ->
    try list_to_atom(S) catch _:_ -> invalid end;
to_atom(_) -> invalid.





