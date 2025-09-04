-module(semp_policy).

-export([is_forbidden/3]).
-on_load(init/0).

-compile({inline, [is_forbidden/3, has_forbidden_prefix/1, prefix/2]}).

-define(PT_MAP,      {semp, forbid_map}).
-define(PT_PREFIXES, {semp, forbid_prefixes}).

%% ---------- Public API ----------

-doc "Purpose:\n"
     "Determines whether a given module/function is forbidden by the sandbox policy. First checks\n"
     "for forbidden module name prefixes, then consults the immutable policy map to block whole\n"
     "modules or specific functions (all arities).\n"
     "\n"
     "Parameters:\n"
     "- `M :: module()` — the module to check.\n"
     "- `F :: atom()` — the function name to check.\n"
     "- `_A :: non_neg_integer()` — arity (not used when the function is banned for all arities).\n"
     "\n"
     "Return Value:\n"
     "- `true` — the module or function is forbidden by policy.\n"
     "- `false` — the call is permitted by policy.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec is_forbidden(module(), atom(), non_neg_integer()) -> boolean().
is_forbidden(M, F, _A) when is_atom(M), is_atom(F) ->
    %% 1) Block internal namespaces quickly
    MBin = atom_to_binary(M, utf8),
    case has_forbidden_prefix(MBin) of
        true  -> true;
        false ->
            %% 2) Lookup in immutable policy
            Map = persistent_term:get(?PT_MAP),
            case maps:get(M, Map, undefined) of
                all -> true;                                % whole module banned
                undefined -> false;
                FMap when is_map(FMap) ->
                    case maps:get(F, FMap, undefined) of
                        all -> true;                        % function banned (ALL arities)
                        _   -> false
                    end
            end
    end.

%% ---------- Initialize once at code load ----------

-doc "Purpose:\n"
     "Initializes persistent configuration for the TRUST system sandboxing policy. Ensures that "
     "the default forbidden prefixes and default deny map are stored in persistent term storage "
     "if not already present.\n"
     "\n"
     "Parameters:\n"
     "- None\n"
     "\n"
     "Return Value:\n"
     "- `ok` — after initialization is complete.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec init() -> ok.
init() ->
    put_unless(?PT_PREFIXES, default_prefixes()),
    put_unless(?PT_MAP,      default_map()),
    ok.


-doc "Purpose:\n"
     "Stores a key-value pair in the persistent term storage only if the key does not already exist. "
     "If the key is present, no action is taken.\n"
     "\n"
     "Parameters:\n"
     "- `Key :: term()` — the persistent term key.\n"
     "- `Val :: term()` — the value to store if the key is not yet defined.\n"
     "\n"
     "Return Value:\n"
     "- `ok` — if the key already exists.\n"
     "- `ok` — after inserting the new value when the key did not exist.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec put_unless(term(), term()) -> ok.
put_unless(Key, Val) ->
    case catch persistent_term:get(Key) of
        {'EXIT', _} -> persistent_term:put(Key, Val);
        _           -> ok
    end.



-doc "Purpose:\n"
     "Determines whether a module name binary begins with any of the configured forbidden prefixes. "
     "Prefixes are retrieved from the persistent term store (`?PT_PREFIXES`).\n"
     "\n"
     "Parameters:\n"
     "- `MBin :: binary()` — the module name as a binary.\n"
     "\n"
     "Return Value:\n"
     "- `true` — if the module name starts with a forbidden prefix.\n"
     "- `false` — otherwise.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n * k), where n = number of prefixes and k = length of each prefix.\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec has_forbidden_prefix(binary()) -> boolean().
has_forbidden_prefix(MBin) ->
    Prefs = persistent_term:get(?PT_PREFIXES),
    lists:any(fun(P) -> prefix(MBin, P) end, Prefs).


-doc "Purpose:\n"
     "Checks whether a binary begins with a given prefix.\n"
     "\n"
     "Parameters:\n"
     "- `Bin :: binary()` — the binary to test.\n"
     "- `Pref :: binary()` — the prefix to check for.\n"
     "\n"
     "Return Value:\n"
     "- `true` — if `Bin` starts with `Pref`.\n"
     "- `false` — otherwise.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(k), where k = byte_size(Pref)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec prefix(binary(), binary()) -> boolean().
prefix(Bin, Pref) when is_binary(Bin), is_binary(Pref) ->
    Sz = byte_size(Pref),
    byte_size(Bin) >= Sz andalso (binary:part(Bin, 0, Sz) =:= Pref).




-doc "Purpose:\n"
     "Provides the default list of module name prefixes considered unsafe when recieved in module names for Module, Function, Arity (MFA) calls from remote Trust Nodes."
     "\n"
     "Parameters:\n"
     "- None\n"
     "\n"
     "Return Value:\n"
     "- `Prefixes :: [binary()]` — a list of binary prefixes such as `<<\"trust_\">>`, "
     "`<<\"semp_\">>`, and `<<\"tempus_\">>`.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec default_prefixes() -> [binary()].
default_prefixes() ->
    [<<"trust_">>, <<"semp_">>, <<"tempus_">>].



-doc "Purpose:\n"
     "Returns the default security policy map for sandboxing/evaluating untrusted code. The map\n"
     "enumerates Erlang/OTP modules and functions that are considered risky and should be denied,\n"
     "either per-function (arity-aware) or at the entire-module level (value `all`). This policy is\n"
     "used as a baseline deny list for system-, I/O-, networking-, code-loading, and VM-control\n"
     "surfaces.\n"
     "\n"
     "Parameters:\n"
     "- None\n"
     "\n"
     "Return Value:\n"
     "- `Policy :: map()` — a map where keys are module atoms and values are either `all` or a\n"
     "  nested map of function atoms to `all`.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec default_map() -> map().
default_map() ->
    #{
      %% ---------- Core Erlang risky functions (ban ALL arities) ----------
      erlang => #{
        %% atom creation / decoding
        list_to_atom              => all,
        list_to_existing_atom     => all,
        binary_to_atom            => all,
        binary_to_existing_atom   => all,
        binary_to_term            => all,

        %% native code / ports / VM control
        load_nif                  => all,
        open_port                 => all,
        port_command              => all,
        ports                     => all,
        port_info                 => all,
        port_control              => all,
        halt                      => all,
        system_flag               => all,
        garbage_collect           => all,

        %% dynamic dispatch / process control
        apply                     => all,
        spawn                     => all,
        spawn_link                => all,
        spawn_monitor             => all,
        spawn_opt                 => all,
        send                      => all,
        exit                      => all,

        %% tracing / monitoring
        trace                     => all,
        trace_pattern             => all,
        system_monitor            => all,
        system_profile            => all,
	loaded                    => all,
	preloaded                 => all,
	%% process control (mutation)
        process_flag  => all,
        group_leader  => all,

        %% process introspection
        process_info  => all,
	processes    => all,

        %% name registry (discovery & takeover)
        register      => all,
        unregister    => all,
        registered    => all,
        whereis       => all,

        %% distribution/auth surface
        set_cookie    => all,

        %% vm/system telemetry
        system_info   => all,
        statistics    => all,

        %% timers & async scheduling (dos vectors)
        send_after    => all,
        start_timer   => all,
        cancel_timer  => all
      },
      %% Parsing/tokenizing/eval toolchain
      unicode   => all,
      erl_parse => all,
      erl_scan  => all,
      erl_eval  => all,
      epp       => all,
      compile   => all,
      %% ---------- Code loading / distributed dispatch ----------
      code  => all,
      rpc   => all,
      erpc  => all,
      trpc  => all,
      erl_ddll => all,

      %% ---------- OS / filesystem / data stores / networking ----------
      os        => all,
      file      => all,
      filelib   => all,
      filename  => all,
      disk_log  => all,
      dets      => all,
      mnesia    => all,

      gen_tcp   => all,
      gen_udp   => all,
      ssl       => all,
      inet      => all,
      inet_tcp  => all,
      inet_udp  => all,
      ssh       => all,
      inets     => all,

      %% ---------- Node/process/system control & registries ----------
      init            => all,   %% (all functions blocked, per your change)
      persistent_term => all,
      global          => all,
      net_adm         => all,
      net_kernel      => all,
      pg              => all,
      sys             => all,

      %% ---------- Tracing frontend / logger mutation ----------
      dbg     => all,
      logger  => all,

      %% ---------- OTP behaviours entry points ----------
      gen_server         => all,
      gen_statem         => all,
      gen_fsm            => all,   %% legacy
      gen_event          => all,
      supervisor         => all,
      supervisor_bridge  => all,
      application        => all,
      %% --- Low-level & prims
      ets             => all,
      prim_file       => all,
      prim_inet       => all,
      erl_prim_loader => all,

      %% --- Archives / compression / regex
      zip     => all,
      erl_tar => all,
      zlib    => all,
      re      => all,

      %% --- Console & timers
      io      => all,
      io_lib  => all,
      timer   => all
    }.
