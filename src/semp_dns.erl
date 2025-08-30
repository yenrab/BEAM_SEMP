-module(semp_dns).
-export([resolve/1]).

%% Resolve a host (or IP literal) to list of inet tuples; port is caller-supplied.
-doc "Purpose:\n"
     "Resolves a host or IP into a list of IP addresses. Accepts binaries, strings, or\n"
     "IPv4/IPv6 tuples. If a literal IP is provided, it is returned as-is in a singleton list;\n"
     "otherwise, DNS lookups are performed for both IPv4 and IPv6.\n"
     "\n"
     "Parameters:\n"
     "- `HostOrIP :: string() | binary() | inet:ip_address()` — hostname or IP to resolve.\n"
     "\n"
     "Return Value:\n"
     "- `{ok, [inet:ip_address()]}` — one or more resolved IP addresses.\n"
     "- `{error, dns_error}` — no addresses could be resolved.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec resolve(string() | binary() | inet:ip_address()) ->
          {ok, [inet:ip_address()]} | {error, dns_error}.
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
