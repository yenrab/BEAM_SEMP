-module(trust_dist).
-moduledoc false.
-export([listen/1, accept/1, connect/3, close/1]).
%% Purpose:
%% Provides secure TLS-based distributed communication for the TRUST system. This module
%% handles the full lifecycle of TRUST client/server connections, including listening for
%% inbound connections, accepting and validating peers, performing post-handshake
%% authorization, issuing and verifying authentication tokens, and managing a token cache.
%%
%% Main Responsibilities:
%% - Opening secure TLS listeners with enforced protocol and certificate settings.
%% - Accepting incoming TLS connections and verifying peer certificates.
%% - Performing server- and client-side post-handshake token exchange and validation.
%% - Resolving hostnames to IPs and attempting outbound TLS connections.
%% - Caching and reissuing tokens securely using ETS for efficiency.
%%
%% Author: Lee Barney
%% Version: 0.1
%% Last Modified: 2025-08-23
%%

-define(CACHE, trust_client_token_cache).



-doc "Purpose:\n"
     "Opens a TLS listening socket on the given port using secure defaults combined "
     "with any application-provided TLS options.\n"
     "\n"
     "Parameters:\n"
     "- `Port :: integer()` — the port number on which the TLS listener should be opened.\n"
     "\n"
     "Return Value:\n"
     "- `{:ok, ssl:sslsocket()}` — the listener socket was successfully opened.\n"
     "- `{:error, term()}` — the listener could not be opened due to configuration or system error.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".
listen(Port) when is_integer(Port) ->
    TlsOpts = lists:flatten([
        {versions, ['tlsv1.3']},
        {alpn_advertised_protocols, [<<"trust/1">>]},
        {verify, verify_peer},
        {fail_if_no_peer_cert, true},
        application:get_env(semp, tls_opts, [])
    ]),
    ssl:listen(Port, TlsOpts).



-doc "Purpose:\n"
     "Accepts an incoming TLS connection from a listening socket, performs the TLS "
     "handshake, and delegates to server_post_handshake/1 upon success.\n"
     "\n"
     "Parameters:\n"
     "- `LSock :: ssl:sslsocket()` — the listening socket from which to accept a client connection.\n"
     "\n"
     "Return Value:\n"
     "- `any()` — success value returned from server_post_handshake/1.\n"
     "- `{:error, tls_error}` — TLS handshake failed.\n"
     "- `{:error, term()}` — other error from ssl:transport_accept/2.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".
accept(LSock) ->
    case ssl:transport_accept(LSock, 5000) of
        {ok, Sock} ->
            case ssl:handshake(Sock, 5000) of
                ok -> server_post_handshake(Sock);
                {error, _} -> ssl:close(Sock), {error, tls_error}
            end;
        E -> E
    end.

-doc "Purpose:\n"
     "Handles post-handshake server-side logic by validating the peer certificate, "
     "checking whitelist status, receiving or issuing tokens, and determining whether "
     "to authorize or reject the connection.\n"
     "\n"
     "Parameters:\n"
     "- `Sock :: ssl:sslsocket()` — the TLS socket representing the client connection.\n"
     "\n"
     "Return Value:\n"
     "- `{ok, ssl:sslsocket(), binary()}` — successful authorization with socket and peer fingerprint.\n"
     "- `{:error, token_invalid}` — client provided an invalid token.\n"
     "- `{:error, bad_frame}` — malformed or unexpected frame received.\n"
     "- `{:error, not_whitelisted}` — client certificate fingerprint not permitted.\n"
     "- `{:error, tls_error}` — TLS peer certificate missing or invalid.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".
server_post_handshake(Sock) ->
    case ssl:peercert(Sock) of
        {ok, CertBin} ->
            FP = semp_util:cert_fingerprint_sha512(CertBin),
            case semp_whitelist:is_allowed(FP) of
                true ->
                    case semp_util:recv_frame(Sock, 1000) of
                        {ok, Bin} ->
                            case safe_term(Bin) of
                                #{t := token_present, token := T} ->
                                    case semp_token:verify(T) of
                                        {ok, #{sub := FP}} -> {ok, Sock, FP};
                                        _ ->
                                            semp_permissions:suspicion_bump(FP, up),
                                            ssl:close(Sock), {error, token_invalid}
                                    end;
                                _ ->
                                    send_token(Sock, FP), {ok, Sock, FP}
                            end;
                        {error, timeout} ->
                            send_token(Sock, FP), {ok, Sock, FP};
                        _ ->
                            ssl:close(Sock), {error, bad_frame}
                    end;
                false ->
                    ssl:close(Sock), {error, not_whitelisted}
            end;
        _ ->
            ssl:close(Sock), {error, tls_error}
    end.

-doc "Purpose:\n"
     "Resolves a hostname or IP address and attempts to establish a TLS connection "
     "on the given port, using the provided or default timeout.\n"
     "\n"
     "Parameters:\n"
     "- `HostOrIP :: string() | inet:ip_address()` — the hostname or IP address of the remote server.\n"
     "- `Port :: integer()` — the port number to connect to.\n"
     "- `Opts :: map()` — connection options.\n"
     "  - `timeout :: integer()` — optional, timeout in milliseconds (default: 5000).\n"
     "\n"
     "Return Value:\n"
     "- `{:ok, ssl:sslsocket()}` — connection successfully established.\n"
     "- `{:error, nxdomain}` — hostname could not be resolved.\n"
     "- `{:error, timeout}` — connection attempt timed out.\n"
     "- `{:error, term()}` — other error during resolution or connection attempt.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: Best O(1), Average O(n), Worst O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".
connect(HostOrIP, Port, Opts) ->
    Timeout = maps:get(timeout, Opts, 5000),
    case semp_dns:resolve(HostOrIP) of
        {ok, [_IP|_]=IPs} -> try_connect(IPs, Port, Timeout);
        E -> E
    end.


-doc "Purpose:\n"
     "Attempts to establish a TLS connection by iterating through a list of candidate "
     "IP addresses until one succeeds or all fail. On success, delegates to "
     "client_post_handshake/1.\n"
     "\n"
     "Parameters:\n"
     "- `IPs :: [inet:ip_address() | string()]` — ordered list of addresses to try.\n"
     "- `Port :: integer()` — the destination port.\n"
     "- `Timeout :: integer()` — the connection timeout in milliseconds.\n"
     "\n"
     "Return Value:\n"
     "- `any()` — success value returned by client_post_handshake/1.\n"
     "- `{:error, connect_failed}` — no connection could be established with any IP.\n"
     "- `{:error, term()}` — error propagated from client_post_handshake/1.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: Best O(1), Worst O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".
try_connect([], _Port, _Tmo) ->
    {error, connect_failed};
try_connect([IP|Rest], Port, Timeout) ->
    TlsOpts = [
        {versions, ['tlsv1.3']},
        {alpn_advertised_protocols, [<<"trust/1">>]},
        {server_name_indication, (case IP of
                                      {_,_,_,_} -> undefined;
                                      {_,_,_,_,_,_,_,_} -> undefined;
                                      _ -> IP
                                  end)},
        {verify, verify_peer}
    ],
    case ssl:connect(IP, Port, TlsOpts, Timeout) of
        {ok, Sock} -> client_post_handshake(Sock);
        {error, _} -> try_connect(Rest, Port, Timeout)
    end.

-doc "Purpose:\n"
     "Performs client-side post-handshake processing by validating the server’s "
     "certificate, checking for a cached token, and either sending the cached token "
     "or receiving a new token issued by the server.\n"
     "\n"
     "Parameters:\n"
     "- `Sock :: ssl:sslsocket()` — the established TLS socket.\n"
     "\n"
     "Return Value:\n"
     "- `{ok, ssl:sslsocket(), binary()}` — connection authorized with socket and fingerprint.\n"
     "- `{:error, protocol_error}` — invalid or unexpected frame received from the server.\n"
     "- `{:error, timeout}` — no valid token frame received within the expected time.\n"
     "- `{:error, tls_error}` — TLS-level failure, such as missing or invalid peer certificate.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".
client_post_handshake(Sock) ->
    case ssl:peercert(Sock) of
        {ok, CertBin} ->
            FP = semp_util:cert_fingerprint_sha512(CertBin),
            case token_for(FP) of
                {ok, Token} ->
                    ok = semp_util:send_frame(Sock, term_to_binary(#{t => token_present, token => Token})),
                    {ok, Sock, FP};
                error ->
                    case semp_util:recv_frame(Sock, 2000) of
                        {ok, Bin} ->
                            case safe_term(Bin) of
                                #{t := token_issue, token := Token} ->
                                    cache_token(FP, Token), {ok, Sock, FP};
                                _ ->
                                    ssl:close(Sock), {error, protocol_error}
                            end;
                        _ ->
                            ssl:close(Sock), {error, timeout}
                    end
            end;
        _ ->
            ssl:close(Sock), {error, tls_error}
    end.

-doc "Purpose:\n"
     "Issues a new token for the given fingerprint and sends it over the TLS socket "
     "as a serialized frame.\n"
     "\n"
     "Parameters:\n"
     "- `Sock :: ssl:sslsocket()` — the TLS socket to send the token through.\n"
     "- `FP :: binary()` — the fingerprint associated with the token.\n"
     "\n"
     "Return Value:\n"
     "- `ok` — the token was successfully sent.\n"
     "- `{:error, term()}` — failure occurred while sending the token frame.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".
send_token(Sock, FP) ->
    {Token, _Kid, _Exp} = semp_token:issue(FP),
    semp_util:send_frame(Sock, term_to_binary(#{t => token_issue, token => Token})).

%% --- local token cache (client side mirror) ---


-doc "Purpose:\n"
     "Stores a token in the ETS cache with its associated fingerprint, expiration time, "
     "and key identifier.\n"
     "\n"
     "Parameters:\n"
     "- `FP :: binary()` — the fingerprint associated with the token.\n"
     "- `Token :: binary()` — the issued authentication token.\n"
     "\n"
     "Return Value:\n"
     "- `ok` — token successfully cached.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".
cache_token(FP, Token) ->
    ensure_cache(),
    ets:insert(?CACHE, {FP, Token, os:system_time(second)+application:get_env(semp, token_ttl, 1200), <<"kid-1">>}), 
    ok.


-doc "Purpose:\n"
     "Retrieves a cached token for the given fingerprint if it exists and has not expired.\n"
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
token_for(FP) ->
    ensure_cache(),
    CurrentTime = os:system_time(second),
    case ets:lookup(?CACHE, FP) of
        [{_, Token, Exp, _}] when Exp > CurrentTime -> {ok, Token};
        _ -> error
    end.

-doc "Purpose:\n"
     "Ensures that the ETS cache table exists. If the table does not exist, it is created; "
     "otherwise, no action is taken.\n"
     "\n"
     "Parameters:\n"
     "- None\n"
     "\n"
     "Return Value:\n"
     "- `ok` — the cache table exists or has been created successfully.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".
ensure_cache() ->
    case ets:info(?CACHE) of
        undefined -> ets:new(?CACHE, [named_table, set, public]);
        _ -> ok
    end, ok.


-doc "Purpose:\n"
     "Closes the given TLS socket.\n"
     "\n"
     "Parameters:\n"
     "- `Sock :: ssl:sslsocket()` — the TLS socket to be closed.\n"
     "\n"
     "Return Value:\n"
     "- `ok` — the socket was successfully closed.\n"
     "- `{:error, term()}` — an error occurred while closing the socket.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-08-23\n".
close(Sock) ->
    ssl:close(Sock).


-doc "Purpose:\n"
     "Safely converts a binary into an Erlang term. If the binary cannot be decoded "
     "safely, a map indicating a bad term is returned instead of raising an exception.\n"
     "\n"
     "Parameters:\n"
     "- `Bin :: binary()` — the binary to decode into a term.\n"
     "\n"
     "Return Value:\n"
     "- `term()` — the decoded Erlang term.\n"
     "- `#{bad_term => true}` — returned if the binary cannot be safely decoded.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-08-23\n".
safe_term(Bin) ->
    try binary_to_term(Bin, [safe]) of T -> T catch _:_ -> #{bad_term => true} end.
