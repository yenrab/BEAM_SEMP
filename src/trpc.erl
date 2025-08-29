%% Purpose:
%% Provides TLS client functionality for the TRUST system. This module handles
%% establishing secure connections, performing client-side post-handshake
%% validation, sending remote call requests, and managing short-lived
%% authentication tokens in an ETS cache.
%%
%% Main Responsibilities:
%% - Resolving hostnames and attempting secure connections across multiple endpoints.
%% - Performing client-side TLS post-handshake certificate validation.
%% - Handling token retrieval, issuance, caching, and expiration.
%% - Sending remote MFA calls over TLS connections and awaiting results.
%% - Providing safe binary-to-term decoding to protect against unsafe data.
%%
%% Author: Lee Barney
%% Version: 0.1
%% Last Modified: 2025-08-23
%%
%%



-module(trpc).
-include("semp.hrl").

-export([cast/5, cast/6,call/5, call/6]).  %% cast/6 and call/6 kept as a compat wrappers; ignore last arg

-define(DEFAULT_TIMEOUT, 5000).
-define(CACHE, ?TOKEN_CACHE_TAB).


-doc "Perform a single remote call over strict TLS (TLS 1.3, mTLS, ALPN = \"trust/1\").\n\n"
     "Resolves HostOrIP to A/AAAA addresses, then attempts TCP+TLS to each endpoint\n"
     "in order using the supplied Port. If a valid token is cached for the server's\n"
     "certificate fingerprint, it is sent first (fast path); otherwise a TOKEN_ISSUE\n"
     "is expected post-handshake. On permission denial or server-side error, the\n"
     "server closes the connection without returning an error frame.\n\n"
     "Options:\n"
     "  • timeout :: non_neg_integer() (milliseconds; default 5000)\n\n"
     "Returns {ok, Value} on success; otherwise {error, Reason} where Reason is one of:\n"
     "dns_error | connect_failed | tls_error | protocol_error | closed | timeout | term()."
    .

-spec call(HostOrIP :: inet:hostname() | inet:ip_address() | binary(),
           Port     :: inet:port_number(),
           MFA      :: {module(), atom(), non_neg_integer()},
           Args     :: [term()],
           Opts     :: #{timeout => non_neg_integer(), _ => term()}) ->
          {ok, term()} |
          {error, dns_error | connect_failed | tls_error | protocol_error | closed | timeout | term()}.
call(HostOrIP, Port, {M,F,A}, Args, Opts) when is_integer(Port) ->
    Timeout = maps:get(timeout, Opts, ?DEFAULT_TIMEOUT),
    case semp_dns:resolve(HostOrIP) of
        {ok, IPs} -> try_endpoints(IPs, Port, {M,F,A}, Args, Timeout);
        {error, _}=E -> E
    end.


-doc "Compatibility wrapper.\n\n"
     "Behaves like call/5 but ignores the sixth argument (kept for source compatibility).\n"
     "TLS verification is always strict (verify_peer); the permissive mode is not supported.\n\n"
     "Prefer calling call/5 directly."
    .

-spec call(HostOrIP :: inet:hostname() | inet:ip_address() | binary(),
           Port     :: inet:port_number(),
           MFA      :: {module(), atom(), non_neg_integer()},
           Args     :: [term()],
           Opts     :: #{timeout => non_neg_integer(), _ => term()},
           _Ignored :: term()) ->
          {ok, term()} |
          {error, dns_error | connect_failed | tls_error | protocol_error | closed | timeout | term()}.
call(HostOrIP, Port, MFA, Args, Opts, _PermissiveTLS) ->
    call(HostOrIP, Port, MFA, Args, Opts).



-doc "Attempt a strict TLS connection to each resolved endpoint in order and perform one RPC.\n\n"
     "Given a non-empty list of IP endpoints (IPv4/IPv6) and a Port, this function iterates\n"
     "sequentially: for each IP it builds strict TLS 1.3 options (ALPN = \"trust/1\",\n"
     "verify_peer, SNI derived from the IP/host) and calls ssl:connect/4. On the first\n"
     "successful TLS session it delegates to the post-handshake path to send the CALL and\n"
     "await the RESULT, then always closes the socket and returns that outcome. If a connect\n"
     "attempt fails, the next endpoint is tried; if all endpoints fail to connect, returns\n"
     "{error, connect_failed}. Any errors after a successful connect (e.g., token/permission\n"
     "failures, protocol issues, timeouts) are propagated from the post-handshake logic.\n\n"
     "Notes:\n"
     "  • Connection policy is sequential (not parallel) and non-permissive (no verify_none).\n"
     "  • Socket is closed on both success and failure after post-handshake processing.\n"
     "  • Per-endpoint connect errors are not surfaced individually—only the terminal\n"
     "    {error, connect_failed} if none succeed."
    .

-spec try_endpoints(IPs     :: [inet:ip_address()],
                    Port    :: inet:port_number(),
                    MFA     :: {module(), atom(), non_neg_integer()},
                    Args    :: [term()],
                    Timeout :: non_neg_integer()) ->
          {ok, term()} |
          {error, connect_failed | tls_error | protocol_error | closed | timeout | term()}.
try_endpoints([], _Port, _MFA, _Args, _Tmo) -> {error, connect_failed};
try_endpoints([IP|Rest], Port, MFA, Args, Timeout) ->
    TlsOpts = tls_client_opts(host_to_sni(IP)),
    case ssl:connect(IP, Port, TlsOpts, Timeout) of
        {ok, Sock} ->
            Res = after_tls(Sock, MFA, Args, Timeout),
            ssl:close(Sock),
            Res;
        {error, _} ->
            try_endpoints(Rest, Port, MFA, Args, Timeout)
    end.


-doc "Derive an Server Name Indication (SNI) hostname for TLS.\n\n"
     "Returns 'undefined' for IPv4/IPv6 tuple literals (SNI must be a DNS hostname per RFC 6066),\n"
     "otherwise returns the input host as-is to be used as the SNI value. This lets callers pass\n"
     "either a DNS name (charlist or binary) or a literal IP address; IPs will suppress SNI."
    .

-spec host_to_sni(HostOrIP :: inet:ip_address() | inet:hostname() | binary()) ->
          SNI :: undefined | inet:hostname() | binary().
host_to_sni({_,_,_,_}) -> undefined;
host_to_sni({_,_,_,_,_,_,_,_}) -> undefined;
host_to_sni(H) -> H.



-doc "Purpose:\n"
     "Performs client-side post-handshake processing after TLS is established: validates the "
     "server certificate, uses a cached token when available or receives a token issuance, "
     "then sends the remote call and awaits the response.\n"
     "\n"
     "Parameters:\n"
     "- `Sock :: ssl:sslsocket()` — established TLS socket.\n"
     "- `{M,F,A} :: {module(), atom(), non_neg_integer()}` — target module, function, and arity.\n"
     "- `Args :: list()` — arguments payload for the remote call.\n"
     "- `Timeout :: integer()` — receive timeout in milliseconds.\n"
     "\n"
     "Return Value:\n"
     "- `Result :: term()` — success value returned by send_call_and_await/4.\n"
     "- `{:error, protocol_error}` — invalid or unexpected protocol frame received.\n"
     "- `{:error, timeout}` — timed out waiting for a required frame.\n"
     "- `{:error, tls_error}` — TLS-level failure (e.g., missing/invalid peer certificate).\n"
     "- `ErrorFromSendCallAndAwait :: term()` — any error returned by send_call_and_await/4 is propagated.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec after_tls(ssl:sslsocket(), {module(), atom(), non_neg_integer()}, list(), integer()) ->
          term()
        | {error, protocol_error}
        | {error, timeout}
        | {error, tls_error}.
after_tls(Sock, {M,F,A}, Args, Timeout) ->
    case ssl:peercert(Sock) of
        {ok, CertBin} ->
            FP = semp_util:cert_fingerprint_sha512(CertBin),
            case token_for(FP) of
                {ok, Token} ->
                    ok = semp_util:send_frame(Sock, term_to_binary(#{t => token_present, token => Token})),
                    send_call_and_await(Sock, {M,F,A}, Args, Timeout);
                error ->
                    case semp_util:recv_frame(Sock, Timeout) of
                        {ok, Bin} ->
                            case safe_term(Bin) of
                                #{t := token_issue, token := Token} ->
                                    cache_token(FP, Token),
                                    send_call_and_await(Sock, {M,F,A}, Args, Timeout);
                                _ -> {error, protocol_error}
                            end;
                        E -> E
                    end
            end;
        _ -> {error, tls_error}
    end.



-doc "Purpose:\n"
     "Sends a remote call request over an established TLS socket and waits for the matching "
     "result. Validates the response shape and request identifier.\n"
     "\n"
     "Parameters:\n"
     "- `Sock :: ssl:sslsocket()` — established TLS socket.\n"
     "- `{M,F,A} :: {module(), atom(), non_neg_integer()}` — target module, function, and arity.\n"
     "- `Args :: [term()]` — argument list; its length must equal `A`.\n"
     "- `Timeout :: integer()` — timeout in milliseconds for send/receive operations.\n"
     "\n"
     "Return Value:\n"
     "- `{ok, term()}` — successful result value from the remote call.\n"
     "- `{:error, protocol_error}` — response was malformed or did not match the request id.\n"
     "- `{:error, closed}` — socket was closed by the peer.\n"
     "- `{:error, timeout}` — no response was received within the timeout.\n"
     "- `OtherError :: term()` — any other error propagated unchanged from lower layers.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec send_call_and_await(
          ssl:sslsocket(),
          {module(), atom(), non_neg_integer()},
          [term()],
          integer()
      ) ->
          {ok, term()}
        | {error, protocol_error}
        | {error, closed}
        | {error, timeout}
        | term().
send_call_and_await(Sock, {M,F,A}, Args, Timeout) when length(Args) =:= A ->
    ReqId = crypto:strong_rand_bytes(12),
    Call = #{t => call, ver => 1, req_id => ReqId, m => M, f => F, a => A, args => Args, opts => #{timeout => Timeout}},
    ok = semp_util:send_frame(Sock, term_to_binary(Call)),
    %% Success: RESULT frame; else server closes silently.
    case semp_util:recv_frame(Sock, Timeout) of
        {ok, Bin} ->
            case safe_term(Bin) of
                #{t := result, req_id := ReqId, value := Val} -> {ok, Val};
                _ -> {error, protocol_error}
            end;
        {error, closed} -> {error, closed};
        {error, timeout} -> {error, timeout};
        Other -> Other
    end.



-doc "Purpose:\n"
     "Safely converts a binary into an Erlang term. If the binary cannot be decoded, "
     "returns a sentinel map instead of raising an exception.\n"
     "\n"
     "Parameters:\n"
     "- `Bin :: binary()` — the binary to decode.\n"
     "\n"
     "Return Value:\n"
     "- `term()` — the decoded Erlang term.\n"
     "- `#{bad_term => true}` — returned if decoding fails.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec safe_term(binary()) -> term() | #{bad_term => true}.
safe_term(Bin) ->
    try binary_to_term(Bin, [safe]) of T -> T catch _:_ -> #{bad_term => true} end.




-doc "Purpose:\n"
     "Builds a set of TLS client options for initiating a secure connection. Always enforces "
     "TLS 1.3, advertises the TRUST protocol, sets the provided SNI, and enables peer "
     "certificate verification.\n"
     "\n"
     "Parameters:\n"
     "- `SNI :: string() | undefined` — the server name indication to include in the TLS handshake.\n"
     "\n"
     "Return Value:\n"
     "- `[{atom(), term()}]` — list of TLS option tuples for use with ssl:connect/4.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec tls_client_opts(string() | undefined) -> [{atom(), term()}].
tls_client_opts(SNI) ->
    Base = [
        {versions, ['tlsv1.3']},
        {alpn_advertised_protocols, [<<"trust/1">>]},
        {server_name_indication, SNI}
    ],
    %% Always strict verification:
    Base ++ [{verify, verify_peer}].


-doc "Purpose:\n"
     "Ensures that the ETS cache table exists. Creates the table if it is undefined; "
     "otherwise, leaves the existing table untouched.\n"
     "\n"
     "Parameters:\n"
     "- None\n"
     "\n"
     "Return Value:\n"
     "- `ok` — the cache table exists or has been successfully created.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec ensure_cache() -> ok.
ensure_cache() ->
    case ets:info(?CACHE) of
        undefined -> ets:new(?CACHE, [named_table, set, public]);
        _ -> ok
    end, 
    ok.



-doc "Purpose:\n"
     "Stores a token in the ETS cache if it contains valid metadata. Extracts expiration "
     "time and key identifier from the token and inserts them alongside the fingerprint. "
     "If the token cannot be parsed, no cache entry is added.\n"
     "\n"
     "Parameters:\n"
     "- `FP :: binary()` — the fingerprint associated with the token.\n"
     "- `Token :: binary()` — the issued authentication token.\n"
     "\n"
     "Return Value:\n"
     "- `ok` — the operation completed; token cached if valid.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec cache_token(binary(), binary()) -> ok.
cache_token(FP, Token) ->
    ensure_cache(),
    case semp_token:peek(Token) of
        {ok, #{exp := Exp, kid := Kid}} -> ets:insert(?CACHE, {FP, Token, Exp, Kid});
        _ -> ok
    end, 
    ok.


-doc "Purpose:\n"
     "Retrieves a cached token for the given fingerprint if present and not expired. "
     "Expired tokens are removed from the cache.\n"
     "\n"
     "Parameters:\n"
     "- `FP :: binary()` — the fingerprint used as the cache lookup key.\n"
     "\n"
     "Return Value:\n"
     "- `{ok, binary()}` — a valid cached token.\n"
     "- `error` — no token found or the token has expired.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec token_for(binary()) -> {ok, binary()} | error.
token_for(FP) ->
    ensure_cache(),
    case ets:lookup(?CACHE, FP) of
        [{_, Token, Exp, _Kid}] ->
            Now = os:system_time(second),
            if
                Exp > Now -> {ok, Token};
                true ->
                    ets:delete(?CACHE, FP),
                    error
            end;
        [] -> error
    end.




%% --- CAST (fire-and-forget) --------------------------------------------------



-doc "Purpose:\n"
     "Resolves the target host or IP and performs a fire-and-forget remote call over TLS by "
     "trying each resolved endpoint with the provided MFA and arguments, honoring the configured timeout.\n"
     "\n"
     "Parameters:\n"
     "- `HostOrIP :: string() | inet:ip_address()` — destination hostname or IP.\n"
     "- `Port :: integer()` — destination port.\n"
     "- `{M,F,A} :: {module(), atom(), non_neg_integer()}` — target module, function, and arity.\n"
     "- `Args :: [term()]` — arguments payload to include in the cast.\n"
     "- `Opts :: map()` — options map.\n"
     "  - `timeout :: integer()` — optional, in milliseconds (default: `?DEFAULT_TIMEOUT`).\n"
     "\n"
     "Return Value:\n"
     "- `Result :: term()` — success value returned by try_endpoints_cast/5.\n"
     "- `{:error, nxdomain}` — hostname could not be resolved.\n"
     "- `{:error, connect_failed}` — all endpoints failed to establish a TLS connection.\n"
     "- `OtherError :: term()` — any other error propagated unchanged from try_endpoints_cast/5.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: Best O(1), Worst O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec cast(
          string() | inet:ip_address(),
          integer(),
          {module(), atom(), non_neg_integer()},
          [term()],
          map()
      ) ->
          term()
        | {error, nxdomain}
        | {error, connect_failed}.
cast(HostOrIP, Port, {M,F,A}, Args, Opts) when is_integer(Port) ->
    Timeout = maps:get(timeout, Opts, ?DEFAULT_TIMEOUT),
    case semp_dns:resolve(HostOrIP) of
        {ok, IPs} -> try_endpoints_cast(IPs, Port, {M,F,A}, Args, Timeout);
        {error, _}=E -> E
    end.



-doc "Purpose:\n"
     "Wrapper for cast/5 that accepts an extra TLS permissiveness argument but ignores it, "
     "delegating directly to cast/5.\n"
     "\n"
     "Parameters:\n"
     "- `HostOrIP :: string() | inet:ip_address()` — destination hostname or IP.\n"
     "- `Port :: integer()` — destination port.\n"
     "- `MFA :: {module(), atom(), non_neg_integer()}` — target module, function, and arity.\n"
     "- `Args :: [term()]` — arguments payload to include in the cast.\n"
     "- `Opts :: map()` — options map.\n"
     "- `_PermissiveTLS :: term()` — ignored argument.\n"
     "\n"
     "Return Value:\n"
     "- `Result :: term()` — value returned by cast/5.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec cast(
          string() | inet:ip_address(),
          integer(),
          {module(), atom(), non_neg_integer()},
          [term()],
          map(),
          term()
      ) -> term().
cast(HostOrIP, Port, MFA, Args, Opts, _PermissiveTLS) ->
    cast(HostOrIP, Port, MFA, Args, Opts).




-doc "Purpose:\n"
     "Attempts to send a fire-and-forget remote call by iterating through a list of candidate "
     "IP addresses until one TLS connection succeeds or all fail. On success, delegates to "
     "after_tls_cast/4 and returns its result.\n"
     "\n"
     "Parameters:\n"
     "- `IPs :: [inet:ip_address() | string()]` — ordered list of destination addresses to try.\n"
     "- `Port :: integer()` — destination port.\n"
     "- `MFA :: {module(), atom(), non_neg_integer()}` — target module, function, and arity.\n"
     "- `Args :: [term()]` — arguments payload for the remote cast.\n"
     "- `Timeout :: integer()` — timeout in milliseconds for connection and cast operations.\n"
     "\n"
     "Return Value:\n"
     "- `Result :: term()` — success value returned by after_tls_cast/4.\n"
     "- `{:error, connect_failed}` — no connection could be established with any IP.\n"
     "- `ErrorFromAfterTLSCast :: term()` — any error returned by after_tls_cast/4 is propagated unchanged.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: Best O(1), Worst O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec try_endpoints_cast(
          [inet:ip_address() | string()],
          integer(),
          {module(), atom(), non_neg_integer()},
          [term()],
          integer()
      ) ->
          term()
        | {error, connect_failed}.
try_endpoints_cast([], _Port, _MFA, _Args, _Tmo) ->
    {error, connect_failed};
try_endpoints_cast([IP | Rest], Port, MFA, Args, Timeout) ->
    TlsOpts = tls_client_opts(host_to_sni(IP)),
    case ssl:connect(IP, Port, TlsOpts, Timeout) of
        {ok, Sock} ->
            Res = after_tls_cast(Sock, MFA, Args, Timeout),
            ssl:close(Sock),
            Res;
        {error, _} ->
            try_endpoints_cast(Rest, Port, MFA, Args, Timeout)
    end.




-doc "Purpose:\n"
     "Performs client-side post-handshake processing for a fire-and-forget call: validates the "
     "server certificate, uses a cached token if available or receives a token issuance, and "
     "then sends the cast without awaiting a result.\n"
     "\n"
     "Parameters:\n"
     "- `Sock :: ssl:sslsocket()` — established TLS socket.\n"
     "- `{M,F,A} :: {module(), atom(), non_neg_integer()}` — target module, function, and arity.\n"
     "- `Args :: [term()]` — arguments payload for the remote cast.\n"
     "- `Timeout :: integer()` — timeout in milliseconds for any required receive during token flow.\n"
     "\n"
     "Return Value:\n"
     "- `ok` — cast was sent successfully.\n"
     "- `{:error, protocol_error}` — invalid or unexpected protocol frame received.\n"
     "- `{:error, timeout}` — timed out waiting for a required frame.\n"
     "- `{:error, tls_error}` — TLS-level failure (e.g., missing/invalid peer certificate).\n"
     "- `OtherError :: term()` — any other error propagated unchanged from lower layers.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec after_tls_cast(
          ssl:sslsocket(),
          {module(), atom(), non_neg_integer()},
          [term()],
          integer()
      ) ->
          ok
        | {error, protocol_error}
        | {error, timeout}
        | {error, tls_error}
        | term().
after_tls_cast(Sock, {M,F,A}, Args, Timeout) ->
    case ssl:peercert(Sock) of
        {ok, CertBin} ->
            FP = semp_util:cert_fingerprint_sha512(CertBin),
            case token_for(FP) of
                {ok, Token} ->
                    ok = semp_util:send_frame(Sock, term_to_binary(#{t => token_present, token => Token})),
                    send_cast(Sock, {M,F,A}, Args);
                error ->
                    case semp_util:recv_frame(Sock, Timeout) of
                        {ok, Bin} ->
                            case safe_term(Bin) of
                                #{t := token_issue, token := Token} ->
                                    cache_token(FP, Token),
                                    send_cast(Sock, {M,F,A}, Args);
                                _ ->
                                    {error, protocol_error}
                            end;
                        E -> E
                    end
            end;
        _ ->
            {error, tls_error}
    end.




-doc "Purpose:\n"
     "Sends a fire-and-forget remote call frame over an established TLS socket. The frame "
     "contains the target MFA and arguments but does not expect a reply.\n"
     "\n"
     "Parameters:\n"
     "- `Sock :: ssl:sslsocket()` — established TLS socket.\n"
     "- `{M,F,A} :: {module(), atom(), non_neg_integer()}` — target module, function, and arity.\n"
     "- `Args :: [term()]` — argument list; its length must equal `A`.\n"
     "\n"
     "Return Value:\n"
     "- `ok` — frame successfully sent.\n"
     "- `{:error, term()}` — an error occurred while sending the frame.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-08-23\n".

-spec send_cast(
          ssl:sslsocket(),
          {module(), atom(), non_neg_integer()},
          [term()]
      ) -> ok | {error, term()}.
send_cast(Sock, {M,F,A}, Args) when length(Args) =:= A ->
    Frame = #{t => cast, ver => 1, m => M, f => F, a => A, args => Args, opts => #{}},
    semp_util:send_frame(Sock, term_to_binary(Frame)),
    ok.
