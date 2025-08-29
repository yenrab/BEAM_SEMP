-module(semp_dns).
-export([resolve/1]).

%% Resolve a host (or IP literal) to list of inet tuples; port is caller-supplied.
resolve(HostOrIP) when is_list(HostOrIP); is_binary(HostOrIP) ->
    H = case HostOrIP of <<_/binary>> -> binary_to_list(HostOrIP); _ -> HostOrIP end,
    case inet:parse_address(H) of
        {ok, IP} -> {ok, [IP]};
        {error, _} ->
            IPv4 = case inet:getaddrs(H, inet) of {ok, L4} -> L4; _ -> [] end,
            IPv6 = case inet:getaddrs(H, inet6) of {ok, L6} -> L6; _ -> [] end,
            case IPv4 ++ IPv6 of [] -> {error, dns_error}; L -> {ok, L} end
    end;
resolve({_,_,_,_}=IP)      -> {ok, [IP]};
resolve({_,_,_,_,_,_,_,_}=IP) -> {ok, [IP]}.
