%%====================================================================
%% File: src/semp_whitelist.erl
%% Purpose: Shared whitelist for TRUST and TEMPUS.
%%   - Two ETS tables (one per profile): trust_whitelist / tempus_whitelist
%%   - Keys   : Fingerprint (raw SHA-512 of client cert DER, binary())
%%   - Values : permission spec
%%        any  -> all modules/functions permitted
%%        none -> handshake ok but no functions permitted
%%        #{Mod => all | [{Fun,Arity}, ...]}
%%   - Whitelist file lives in the CONSUMING app’s priv/, not in beam_semp.
%%     Keys in the file are CERT FILENAMES (e.g. "client.pem").
%%====================================================================
-module(semp_whitelist).

-export([
    %% table management
    table/1,
    ensure/1,
    reload/1,

    %% queries
    is_allowed/2,

    %% path helpers
    whitelist_path/1
]).

%% ---------- ETS tables (per profile) ----------
-define(TAB_TRUST,  trust_whitelist).
-define(TAB_TEMPUS, tempus_whitelist).

%% ---------- Public API ----------


-doc "Purpose:\n"
     "Returns the ETS table identifier associated with the given protocol. "
     "Supports mapping for `trust` and `tempus` protocols.\n"
     "\n"
     "Parameters:\n"
     "- `Namespace :: trust | tempus` — the desired protocol.\n"
     "\n"
     "Return Value:\n"
     "- `ets:tid()` — the ETS table identifier corresponding to the namespace.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-06\n".

-spec table(trust | tempus) -> ets:tid().
table(trust)  -> ?TAB_TRUST;
table(tempus) -> ?TAB_TEMPUS.



-doc "Purpose:\n"
     "Ensures that the whitelist ETS table for the given profile exists and is populated. "
     "If the table does not exist, it is created, then populated from the profile's whetelist file found in the priv directory. "
     "Logs a debug message when a new table is loaded from disk.\n"
     "\n"
     "Parameters:\n"
     "- `Profile :: atom()` — profile identifier used to determine the ETS table name. Either trust or tempus.\n"
     "\n"
     "Return Value:\n"
     "- `Table :: ets:tid()` — the ETS table identifier for the profile’s whitelist.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.2\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-06\n".

-spec ensure(trust | tempus) -> ets:tid().
ensure(Profile) ->
    case ets:info(table(Profile)) of
        undefined ->
            _ = ets:new(table(Profile), [named_table, set, protected, {read_concurrency, true}]),
            load_from_priv(Profile),
	    logger:debug("trust_whitelist: loaded list from priv/whitelist.config");
        _ ->
           ok 
    end,
    table(Profile).


-doc "Purpose:\n"
     "Reloads the whitelist ETS table for the given profile. Deletes the existing table if present "
     "and ensures a fresh table is created and reloaded from the whitelist file associated with the provided profile found in the priv directory.\n"
     "\n"
     "Parameters:\n"
     "- `Profile :: atom()` — profile identifier used to determine the ETS table name. Either trust or tempus\n"
     "\n"
     "Return Value:\n"
     "- `Table :: ets:tid()` — the ETS table identifier for the reloaded profile whitelist.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.2\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-06\n".

-spec reload(trust | tempus) -> ets:tid().
reload(Profile) ->
    try ets:delete(table(Profile))
    catch
        _ -> ok   % table didn't exist (or wasn't yours)
    end,
    ensure(Profile).



-doc "Purpose:\n"
     "Loads whitelist data for a given profile from the prfile's associated whitelist file found in the priv directory. First attempts "
     "to auto-load certificates from `priv/certs` with a default spec, then applies explicit overrides "
     "from the whitelist file if present. If no whitelist file is found, logs a warning and the node behaves "
     "as independent (rejecting all). If the file is invalid, the whitelist remains empty.\n"
     "\n"
     "Parameters:\n"
     "- `Profile :: trust | tempus` — profile identifier determining which whitelist to load.\n"
     "\n"
     "Return Value:\n"
     "- `ok` — whitelist loaded successfully or handled gracefully when no config was found.\n"
     "- `fail` — whitelist config file was missing or invalid.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.2\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-06\n".

-spec load_from_priv(trust | tempus) -> ok | fail.
load_from_priv(Profile) ->
    %% First, optionally auto-load every cert in priv/certs with a default spec
    maybe_autoload_from_certs(Profile),
    %% Then apply explicit overrides from whitelist.config (if present)
    case whitelist_path(Profile) of
        fail ->
	    %% No priv dir available -> behave as independent node (reject all).
            logger:warning("whitelist.config not found. Running as independent/client node."),
            ok;
        Path ->
            case file:consult(Path) of
                {ok, [Map]} when is_map(Map) ->
                    load_spec_map(Profile, Map), ok;
                _ ->
                    %% Missing/invalid file -> empty whitelist
                    fail
            end
    end.





-doc "Purpose:\n"
     "Optionally auto-loads every certificate in `priv/certs` for the given profile using a default "
     "authorization spec. Explicit configuration from the whitelist data  may override these entries. "
     "If the default authorization spec is invalid, logs a warning and skips autoloading.\n"
     "\n"
     "Parameters:\n"
     "- `Profile :: trust | tempus` — profile identifier determining which whitelist table to populate.\n"
     "\n"
     "Return Value:\n"
     "- `ok` — always, after attempting to autoload certificates.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.2\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-06\n".

-spec maybe_autoload_from_certs(trust | tempus) -> ok.
maybe_autoload_from_certs(Profile) ->
    case application:get_env(semp, whitelist_autoload, false) of
        true ->
            DefaultAuthorization = application:get_env(trust, whitelist_default_spec, []),
            case normalize_value(DefaultAuthorization) of
                invalid ->
                    logger:warning("whitelist: invalid default authorization ~p; autoload skipped", [DefaultAuthorization]),
                    ok;
                DefaultSpec ->
                    Dir = whitelist_path(Profile),
                    Files = list_cert_files(Dir),
                    lists:foreach(
                      fun(Path) ->
                          case read_cert_fp(Path) of
                              {ok, FP} ->
                                  %% insert_new so explicit config can override later
                                  _ = ets:insert_new(table(Profile), {FP, DefaultSpec}),
                                  ok;
                              {error, Reason} ->
                                  logger:warning("whitelist: skipping ~ts (~p)", [Path, Reason])
                          end
                      end, Files),
                    ok
            end;
        false ->
            ok
    end.




-doc "Purpose:\n"
     "Checks whether a given fingerprint is allowed for the specified profile by verifying its "
     "presence in the corresponding whitelist ETS table.\n"
     "\n"
     "Parameters:\n"
     "- `Profile :: trust | tempus` — profile identifier selecting the whitelist table.\n"
     "- `FP :: binary()` — certificate fingerprint to check.\n"
     "\n"
     "Return Value:\n"
     "- `true` — if the fingerprint is present in the whitelist.\n"
     "- `false` — if the fingerprint is not whitelisted.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.2\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-06\n".

-spec is_allowed(trust | tempus, binary()) -> boolean().
is_allowed(Profile, FP) when is_binary(FP) ->
    ensure(Profile),
    ets:member(table(Profile), FP).




-doc "Purpose:\n"
     "Determines the full filesystem path to the whitelist configuration file for the given profile. "
     "Uses the application environment key `whitelist_file` from the profile application and resolves it "
     "relative to the application’s `priv` directory. Returns `fail` if no valid file exists.\n"
     "\n"
     "Parameters:\n"
     "- `Profile :: trust | tempus` — profile identifier selecting which application environment to use.\n"
     "\n"
     "Return Value:\n"
     "- `Path :: string()` — absolute path to the whitelist data file.\n"
     "- `fail` — if the `priv` directory or whitelist file cannot be found.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.2\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-06\n".

-spec whitelist_path(trust | tempus) -> string() | fail.
whitelist_path(Profile) ->
    case priv_dir() of
        fail -> fail;
        Dir  ->
                case application:get_env(Profile, whitelist_file) of
                    {ok, Name} when is_list(Name); is_binary(Name) -> 
				NameString = to_list(Name),
				Path = filename:join(Dir, NameString),
				case filelib:is_file(Path) of
					false -> fail;
					_     -> Path
				end;

                    _ -> fail
                end
    end.





-doc "Purpose:\n"
     "Loads a specification map into the whitelist ETS table for the given profile. Iterates over the "
     "map entries, inserting each into the table via `insert_entry/3`. After loading, logs the contents "
     "of the whitelist table for debugging.\n"
     "\n"
     "Parameters:\n"
     "- `Profile :: trust | tempus` — profile identifier selecting the target whitelist table.\n"
     "- `Map :: map()` — specification map of fingerprints and their associated authorization specs.\n"
     "\n"
     "Return Value:\n"
     "- `ok` — after all entries have been inserted and the table logged.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.2\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-06\n".

-spec load_spec_map(trust | tempus, map()) -> ok.
load_spec_map(Profile, Map) ->
            maps:foreach(
              fun(K, V) ->
                  insert_entry(Profile, K, V)
              end, Map),
	      logger:debug("Whitelist table for ~p is ~p~n",[Profile, ets:foldl(fun(E, Acc) -> io:format("~p~n", [E]), Acc end, ok, table(Profile))]),
           ok.



-doc "Purpose:\n"
     "Inserts a certificate fingerprint and its authorization spec into the whitelist ETS table for "
     "the given profile. Reads the certificate file, extracts its fingerprint, normalizes the spec, "
     "and inserts it. Invalid specs or read errors are logged as warnings.\n"
     "\n"
     "Parameters:\n"
     "- `Profile :: trust | tempus` — profile identifier selecting the target whitelist table.\n"
     "- `FileName :: string() | binary() | atom()` — certificate file name relative to the certs directory.\n"
     "- `Value :: term()` — raw authorization spec that will be normalized before insertion.\n"
     "\n"
     "Return Value:\n"
     "- `ok` — always, after attempting to insert or log the issue.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.2\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-06\n".

-spec insert_entry(trust | tempus, string() | binary() | atom(), term()) -> ok.
insert_entry(Profile, FileName, Value) ->
    CertPath = cert_path(FileName),
    case read_cert_fp(CertPath) of
        {ok, FP} ->
            case normalize_value(Value) of
                invalid -> logger:warning("whitelist: invalid spec for ~ts",[FileName]),
			   ok;
                Spec    -> ets:insert(table(Profile), {FP, Spec}), 
			   logger:debug("whitelist: added ~ts -> ~p",[FileName, Spec]),
			   ok
            end;
        {error, Reason} ->
            logger:warning("whitelist: skipping ~ts (~p)", [CertPath, Reason]),
            ok
    end.






-doc "Purpose:\n"
     "Lists all certificate files in the given directory that match common extensions (`.pem`, `.crt`, `.cer`). "
     "Collects and returns the unique set of matching files in sorted order.\n"
     "\n"
     "Parameters:\n"
     "- `Dir :: string()` — directory path to search for certificate files.\n"
     "\n"
     "Return Value:\n"
     "- `Files :: [string()]` — sorted list of unique certificate file paths.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.2\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n log n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-09-06\n".

-spec list_cert_files(string()) -> [string()].
list_cert_files(Dir) ->
    %% Pick the extensions you use; adjust as needed
    Pems = filelib:wildcard(filename:join(Dir, "*.pem")),
    Crts = filelib:wildcard(filename:join(Dir, "*.crt")),
    Cers = filelib:wildcard(filename:join(Dir, "*.cer")),
    lists:usort(Pems ++ Crts ++ Cers).




-doc "Purpose:\n"
     "Resolves the full filesystem path for a certificate file located under the `certs` directory "
     "of the application’s `priv` directory. Returns `fail` if the application’s priv directory "
     "cannot be determined.\n"
     "\n"
     "Parameters:\n"
     "- `FileName :: string() | binary() | atom()` — certificate file name.\n"
     "\n"
     "Return Value:\n"
     "- `Path :: string()` — full path to the certificate file under `priv/certs`.\n"
     "- `fail` — if the application’s priv directory is not available.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.2\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-06\n".

-spec cert_path(string() | binary() | atom()) -> string() | fail.
cert_path(FileName) ->
    case priv_app() of
        fail -> fail;
        App  ->
            case code:priv_dir(App) of
                Dir when is_list(Dir) -> filename:join([Dir, "certs", FileName]);
                {error, _}            -> fail
            end
    end.





-doc "Purpose:\n"
     "Normalizes a whitelist authorization specification. Accepts `any`, `none`, or a list of\n"
     "entries mapping a module to `any` (module-wide allow) or to an explicit list of `{Function, Arity}`\n"
     "pairs. Invalid inputs yield `invalid`.\n"
     "\n"
     "Parameters:\n"
     "- `any | none | List :: list()` — entries like `{Mod, any}` or `{Mod, [{Fun, Arity}, ...]}`.\n"
     "\n"
     "Return Value:\n"
     "- `any` — unrestricted.\n"
     "- `none` — no permissions.\n"
     "- `Map :: #{module() => all | [{atom(), non_neg_integer()}]}` — normalized spec.\n"
     "- `invalid` — malformed input.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.2\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-09-06\n".

-spec normalize_value(any | none | list() | term()) ->
          any | none | #{module() => all | [{atom(), non_neg_integer()}]} | invalid.
normalize_value(any)  -> any;
normalize_value(none) -> none;
normalize_value(List) when is_list(List) ->
    try lists:foldl(
            fun
                ({Mod, any}, Acc) when is_atom(Mod) ->
                    Acc#{ Mod => all };
                ({Mod, FAs}, Acc) when is_atom(Mod), is_list(FAs) ->
                    Allowed = [ {F,A} || {F,A} <- FAs, is_atom(F), is_integer(A) ],
                    case Allowed of [] -> Acc; _ -> Acc#{ Mod => Allowed } end;
                (_, Acc) -> Acc
            end, #{}, List)
    catch _:_ -> invalid end;
normalize_value(_) -> invalid.




-doc "Purpose:\n"
     "Reads a certificate file and extracts its fingerprint. Supports PEM-encoded certificates and\n"
     "returns the raw 64-byte SHA-512 fingerprint of the DER-encoded certificate. If no certificate\n"
     "entry is found in the file, or if the file cannot be read, an error is returned.\n"
     "\n"
     "Parameters:\n"
     "- `Path :: string()` — filesystem path to the certificate file.\n"
     "\n"
     "Return Value:\n"
     "- `{ok, binary()}` — raw 64-byte certificate fingerprint.\n"
     "- `{error, no_certificate_entry}` — file contained no certificate entry.\n"
     "- `{error, term()}` — file could not be read.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.2\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-06\n".

-spec read_cert_fp(string()) -> {ok, binary()} | {error, no_certificate_entry} | {error, term()}.
read_cert_fp(Path) ->
    case file:read_file(Path) of
        {ok, Bin} ->
            case public_key:pem_decode(Bin) of
                [{'Certificate', Der, _} | _] ->
                    {ok, semp_util:cert_fingerprint_sha512(Der)};  %% RAW 64-byte binary
                [] ->
                    {error, no_certificate_entry}
            end;
        {error, E} -> {error, E}
    end.





-doc "Purpose:\n"
     "Resolves the `priv` directory for the current application. Returns the directory path if it "
     "can be determined, otherwise returns `fail`.\n"
     "\n"
     "Parameters:\n"
     "- None\n"
     "\n"
     "Return Value:\n"
     "- `Dir :: string()` — the application’s priv directory path.\n"
     "- `fail` — if the priv directory cannot be resolved.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.2\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-06\n".

-spec priv_dir() -> string() | fail.
priv_dir() ->
    case priv_app() of
        fail -> fail;
        App  ->
            case code:priv_dir(App) of
                Dir when is_list(Dir) -> Dir;
                {error, _} -> fail
            end
    end.





-doc "Purpose:\n"
     "Resolves the application that owns the `priv` directory by checking the `host_app` setting "
     "in the `beam_semp` application environment. Returns the application atom if configured, "
     "otherwise `fail`.\n"
     "\n"
     "Parameters:\n"
     "- None\n"
     "\n"
     "Return Value:\n"
     "- `App :: atom()` — the application configured as the host.\n"
     "- `fail` — if the environment key is missing or invalid.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-06\n".

-spec priv_app() -> atom() | fail.
priv_app() ->
    case application:get_env(beam_semp, host_app) of
        {ok, App} when is_atom(App) -> App;
        _ -> fail
    end.



-doc "Purpose:\n"
     "Converts a binary or list into a list representation. If the input is already a list, it is "
     "returned unchanged. Intended for normalizing values before working with filenames or paths.\n"
     "\n"
     "Parameters:\n"
     "- `B :: binary()` — a UTF-8 encoded binary.\n"
     "- `L :: string()` — a list (string) value.\n"
     "\n"
     "Return Value:\n"
     "- `string()` — list representation of the input.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-09-06\n".

-spec to_list(binary() | string()) -> string().
to_list(B) when is_binary(B) -> binary_to_list(B);
to_list(L) when is_list(L)   -> L.
