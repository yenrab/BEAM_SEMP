-module(trpc_loader).
-export([load_api/0]).


-doc "Purpose:\n"
     "Loads and preloads API modules defined in the application environment under the `rpc_api` key. "
     "Ensures each listed module is loaded into the VM using `ensure_mod_loaded/1`. If the environment "
     "key is missing or invalid, no modules are loaded.\n"
     "\n"
     "Parameters:\n"
     "- None\n"
     "\n"
     "Return Value:\n"
     "- `ok` — always, after attempting to load all configured modules.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-05\n".

-spec load_api() -> ok.
load_api() ->
    Mods = case application:get_env(trust, rpc_api) of
               {ok, L} when is_list(L) -> L;
               _ -> []
           end,
    lists:foreach(fun ensure_mod_loaded/1, Mods),
    ok.



-doc "Purpose:\n"
     "Ensures that a given module is loaded into the VM. If the module cannot be loaded, logs a warning "
     "but does not fail. This allows optional modules to be handled gracefully without crashing the system.\n"
     "\n"
     "Parameters:\n"
     "- `M :: atom()` — the module to ensure is loaded.\n"
     "\n"
     "Return Value:\n"
     "- `ok` — whether the module was successfully loaded, failed to load, or is otherwise unavailable.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-05\n".

-spec ensure_mod_loaded(atom()) -> ok.
ensure_mod_loaded(M) when is_atom(M) ->
    case code:ensure_loaded(M) of
        {module, M} -> ok;
        {error, Reason} ->
            %% not fatal; you can choose to error out if you want strictness
            logger:warning("rpc_api preload: ~p not loaded (~p)", [M, Reason]),
            ok;
        _ -> ok
    end.
