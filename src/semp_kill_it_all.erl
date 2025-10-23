-module(semp_kill_it_all).
-export([std_distribution/0]).


std_distribution() ->
    %% 0) Don't crash if kernel is already loaded.
    _ = (catch application:load(kernel)),
    %% 1) Never auto-connect
    ok = application:set_env(kernel, dist_auto_connect, never),

    %% 2) Drop any existing node links
    lists:foreach(fun erlang:disconnect_node/1, nodes()),

    %% 3) Stop distribution entirely (kills distributed gen_server, rpc, global, etc.)
    catch net_kernel:stop(),
    %% emit an urgent message with a domain tag as metadata
    semp_io:print_color([bold,red],"Standard distribution is OFF.",[]),
    %% 4) Optional: kill erpc & rpc usage anywhere in this VM (policy)
    disallow_erpc_and_rpc().
    

disallow_erpc_and_rpc() ->
    %% Start tracer (idempotent)
    _ = case dbg:get_tracer() of
            undefined -> dbg:tracer(process, {fun handle_trace/2, #{}});
            _Pid      -> {ok, already_started}
        end,

    %% Trace calls in existing AND future processes
    dbg:p(all, [call]),
    dbg:p(new, [call]),

    %% Matchspec that matches any call (no fun2ms needed)
    MS = [{'_',[true],[]}],

    %% erpc API
    dbg:tpl(erpc, call,      4, MS),
    dbg:tpl(erpc, call,      5, MS),
    dbg:tpl(erpc, cast,      4, MS),
    dbg:tpl(erpc, cast,      5, MS),
    dbg:tpl(erpc, multicall, 5, MS),
    dbg:tpl(erpc, multicall, 6, MS),

    %% classic rpc API
    dbg:tpl(rpc,  call,      4, MS),
    dbg:tpl(rpc,  call,      5, MS),
    dbg:tpl(rpc,  cast,      4, MS),     
    dbg:tpl(rpc,  async_call,4, MS),
    dbg:tpl(rpc,  multicall, 4, MS),
    dbg:tpl(rpc,  multicall, 5, MS),

    ok.

%% handler: kill the *caller*
handle_trace({trace, Pid, call, {Mod, _Fun, _Args}} = _Evt, S)
  when Mod =:= erpc; Mod =:= rpc ->
    exit(Pid, erpc_disabled),
    S;
handle_trace(_Evt, S) ->
    S.
