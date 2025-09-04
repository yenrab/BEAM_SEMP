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

-export([cast/4, cast/5,call/4, call/5]). 

-define(DEFAULT_TIMEOUT, 5000).
-define(CACHE, ?TOKEN_CACHE_TAB).


-doc "Purpose:\n"
     "Performs a fire-and-forget remote invocation by resolving a host or IP, then attempting "
     "to connect and send the specified MFA with arguments. Delegates to try_endpoints/6 with "
     "operation type `cast`.\n"
     "\n"
     "Parameters:\n"
     "- `HostOrIP :: string() | binary() | inet:ip_address()` — destination hostname or IP.\n"
     "- `Port :: integer()` — remote port to connect to.\n"
     "- `{M,F,A} :: {module(), atom(), integer()}` — target module, function, and arity.\n"
     "- `Args :: [term()]` — arguments to pass to the remote function.\n"
     "- `Opts :: map()` — options; may include `timeout` (ms), default `?DEFAULT_TIMEOUT`.\n"
     "\n"
     "Return Value:\n"
     "- `Result :: term()` — success value propagated from try_endpoints/6.\n"
     "- `{error, dns_error}` — hostname could not be resolved.\n"
     "- `{error, connect_failed}` — all endpoints failed to connect.\n"
     "- `{error, term()}` — other error from resolution or connection.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: Best O(1), Worst O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec cast(
          string() | binary() | inet:ip_address(),
          integer(),
          {module(), atom(), integer()},
          [term()],
          map()
      ) ->
          term()
        | {error, dns_error}
        | {error, connect_failed}
        | {error, term()}.
cast(HostOrIP, Port, {M,F,A}, Args, Opts) when is_integer(Port) ->
    Timeout = maps:get(timeout, Opts, ?DEFAULT_TIMEOUT),
    logger:info("trpc: Casting (~p, ~p) to ~p on port ~p with args ~p.~n",[{M,F,A},Args,HostOrIP,Port,Opts]),
    case semp_dns:resolve(HostOrIP) of
        {ok, IPs} -> try_endpoints(cast, IPs, Port, {M,F,A}, Args, Timeout);
        {error, _}=E -> E
    end.


-doc "Purpose:\n"
     "Convenience wrapper for `cast/5` that performs a fire-and-forget remote invocation with "
     "default options. Delegates to `cast/5` using an empty map for options.\n"
     "\n"
     "Parameters:\n"
     "- `HostOrIP :: string() | binary() | inet:ip_address()` — destination hostname or IP.\n"
     "- `Port :: integer()` — remote port to connect to.\n"
     "- `MFA :: {module(), atom(), integer()}` — target module, function, and arity.\n"
     "- `Args :: [term()]` — arguments to pass to the remote function.\n"
     "\n"
     "Return Value:\n"
     "- `Result :: term()` — success value propagated from `cast/5`.\n"
     "- `{error, dns_error}` — hostname could not be resolved.\n"
     "- `{error, connect_failed}` — all endpoints failed to connect.\n"
     "- `{error, term()}` — other error from resolution or connection.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: Best O(1), Worst O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec cast(
          string() | binary() | inet:ip_address(),
          integer(),
          {module(), atom(), integer()},
          [term()]
      ) ->
          term()
        | {error, dns_error}
        | {error, connect_failed}
        | {error, term()}.
cast(HostOrIP, Port, MFA, Args) ->
    cast(HostOrIP, Port, MFA, Args, #{}).

-doc "Purpose:\n"
     "Initiates a synchronous remote call over TRUST by resolving a host or IP, then attempting "
     "to connect and invoke the given MFA with arguments. Delegates to try_endpoints/6 to attempt "
     "the connection and execution across resolved IPs.\n"
     "\n"
     "Parameters:\n"
     "- `HostOrIP :: string() | binary() | inet:ip_address()` — the target hostname or IP address.\n"
     "- `Port :: integer()` — the remote port to connect to.\n"
     "- `{M,F,A} :: {module(), atom(), integer()}` — the MFA to invoke remotely.\n"
     "- `Args :: [term()]` — arguments for the remote function.\n"
     "- `Opts :: map()` — call options, may include `timeout` in milliseconds (defaults to `?DEFAULT_TIMEOUT`).\n"
     "\n"
     "Return Value:\n"
     "- `Result :: term()` — the result of the remote call on success.\n"
     "- `{error, dns_error}` — host resolution failed.\n"
     "- `{error, term()}` — any error propagated from resolution or connection.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec call(string() | binary() | inet:ip_address(), integer(), {module(), atom(), integer()}, [term()], map()) ->
          term() | {error, term()}.
call(HostOrIP, Port, {M,F,A}, Args, Opts) when is_integer(Port) ->
    Timeout = maps:get(timeout, Opts, ?DEFAULT_TIMEOUT),
    case semp_dns:resolve(HostOrIP) of
        {ok, IPs} ->
	    try_endpoints(call, IPs, Port, {M,F,A}, Args, Timeout);
        {error, _}=E -> 
	    E
    end.



-doc "Purpose:\n"
     "Convenience wrapper for `call/5` that initiates a synchronous remote call using default options. "
     "Delegates to `call/5` with an empty map for options.\n"
     "\n"
     "Parameters:\n"
     "- `HostOrIP :: string() | binary() | inet:ip_address()` — the target hostname or IP address.\n"
     "- `Port :: integer()` — the remote port to connect to.\n"
     "- `MFA :: {module(), atom(), integer()}` — the MFA to invoke remotely.\n"
     "- `Args :: [term()]` — arguments for the remote function.\n"
     "\n"
     "Return Value:\n"
     "- `Result :: term()` — the result of the remote call on success.\n"
     "- `{error, term()}` — error propagated from resolution or connection.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec call(string() | binary() | inet:ip_address(), integer(), {module(), atom(), integer()}, [term()]) ->
          term() | {error, term()}.
call(HostOrIP, Port, MFA, Args) ->
    call(HostOrIP, Port, MFA, Args, #{}).



-doc "Purpose:\n"
     "Attempts a remote operation (`call` or `cast`) by iterating through resolved IP endpoints. "
     "For each IP, establishes a TLS connection with SNI, configures the socket for passive/binary "
     "mode, delegates to `after_tls/5`, then closes the socket. Continues to the next IP on failure "
     "until one succeeds or all are exhausted.\n"
     "\n"
     "Parameters:\n"
     "- `CallType :: call | cast` — operation type controlling post-TLS behavior and reply handling.\n"
     "- `IPs :: [inet:ip_address() | string()]` — ordered list of destination addresses to try.\n"
     "- `Port :: integer()` — destination port.\n"
     "- `MFA :: {module(), atom(), integer()}` — target module, function, and arity.\n"
     "- `Args :: [term()]` — arguments passed to the remote function.\n"
     "- `Timeout :: integer()` — connection (and subsequent receive) timeout in milliseconds.\n"
     "\n"
     "Return Value:\n"
     "- `Result :: term()` — success value returned by `after_tls/5` for the first successful endpoint.\n"
     "- `{error, connect_failed}` — no endpoint could be connected successfully.\n"
     "- `OtherError :: term()` — any error propagated unchanged from `after_tls/5`.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: Best O(1), Worst O(n)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec try_endpoints(
          call | cast,
          [inet:ip_address() | string()],
          integer(),
          {module(), atom(), integer()},
          [term()],
          integer()
      ) ->
          term()
        | {error, connect_failed}.
try_endpoints(_CallType, [], _Port, _MFA, _Args, _Tmo) -> {error, connect_failed};
try_endpoints(CallType, [IP|Rest], Port, MFA, Args, Timeout) ->
    TlsOpts = tls_client_opts(host_to_sni(IP)),
    logger:info("try_endpoints: about to connect IP: ~p~n",[IP]),
    case ssl:connect(IP, Port, TlsOpts, Timeout) of
        {ok, Sock} ->
		    logger:info("ssl:connect got socket: ~p~n",[Sock]),
		    ok = ssl:setopts(Sock, [{active, false}, {mode, binary}]),
            Res = after_tls(CallType, Sock, MFA, Args, Timeout),
            ssl:close(Sock),
            Res;
        {error, Reason} ->
		    logger:info("connect to ~p:~p failed: ~p~nTrying next IP ~p~n", [IP, Port, Reason,Rest]),
	    try_endpoints(CallType,Rest, Port, MFA, Args, Timeout)
    end.

-doc "Purpose:\n"
     "Converts a host or IP address into an appropriate Server Name Indication (SNI) value for TLS. "
     "IPv4 and IPv6 addresses return `undefined` (no SNI), while hostnames are returned unchanged.\n"
     "\n"
     "Parameters:\n"
     "- `Host :: inet:ip4_address() | inet:ip6_address() | string() | binary()` — the host or IP.\n"
     "\n"
     "Return Value:\n"
     "- `undefined` — if the input is an IPv4 or IPv6 address.\n"
     "- `Host` — if the input is a hostname.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(1)\n"
     "- Space: O(1)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec host_to_sni(inet:ip4_address() | inet:ip6_address() | string() | binary()) ->
          undefined | string() | binary().
host_to_sni({_,_,_,_}) -> undefined;
host_to_sni({_,_,_,_,_,_,_,_}) -> undefined;
host_to_sni(H) -> H.


-doc "Purpose:\n"
     "Completes client-side post-TLS processing for a remote operation (`call` or `cast`). "
     "Verifies the server certificate, attempts a token fast-path using a cached token, or "
     "receives a newly issued token from the server, caches it, and then delegates to "
     "send_and_maybe_wait/5 to transmit the request and (for calls) await the result. "
     "Protocol or transport errors are returned as `{error, ...}` tuples; unexpected crashes "
     "are wrapped and returned.\n"
     "\n"
     "Parameters:\n"
     "- `CallType :: call | cast` — operation type controlling reply behavior.\n"
     "- `Sock :: ssl:sslsocket()` — established TLS socket.\n"
     "- `{M,F,A} :: {module(), atom(), non_neg_integer()}` — target module, function, and arity.\n"
     "- `Args :: [term()]` — arguments for the remote function.\n"
     "- `Timeout :: integer()` — timeout in milliseconds for token receive and request flow.\n"
     "\n"
     "Return Value:\n"
     "- `Result :: term()` — success value returned by send_and_maybe_wait/5.\n"
     "- `{error, {peer_cert_error, term()}}` — server certificate retrieval failed.\n"
     "- `{error, {protocol_error, term()}}` — unexpected or invalid protocol frame.\n"
     "- `{error, {recv_failed, term()}}` — transport receive error.\n"
     "- `{error, {client_after_tls_crash, term(), term(), term()}}` — unexpected crash; socket closed.\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec after_tls(
          call | cast,
          ssl:sslsocket(),
          {module(), atom(), non_neg_integer()},
          [term()],
          integer()
      ) ->
          term()
        | {error, {peer_cert_error, term()}}
        | {error, {protocol_error, term()}}
        | {error, {recv_failed, term()}}
        | {error, {client_after_tls_crash, term(), term(), term()}}.
after_tls(CallType, Sock, {M,F,A}, Args, Timeout) ->
    try
        %% 1) Server certificate (diagnose here if it fails)
        FP =
            case ssl:peercert(Sock) of
                {ok, CertDer}   -> semp_util:cert_fingerprint_sha512(CertDer);
                {error, Reason} -> throw({peer_cert_error, Reason})
            end,

        %% 2) Token fast path
        case token_for(FP) of
            {ok, Token} ->
		logger:info("trpc: sending cached token ~p~n",[Token]),
                ok = semp_util:send_frame(Sock, term_to_binary(#{t => token_present, token => Token})),
                send_and_maybe_wait(CallType, Sock, {M,F,A}, Args, Timeout);
            error ->
                %% 3) Expect TOKEN_ISSUE
		logger:info("trpc: waiting for server token"),
                case semp_util:recv_frame(Sock, Timeout) of
                    {ok, Bin} ->
			logger:info("received binary token from server."),
                        case safe_term(Bin) of
                            #{t := token_issue, token := Token} ->
				logger:info("trpc: received safe server token ~p~n",[Token]),
                                cache_token(FP, Token),
                                send_and_maybe_wait(CallType, Sock, {M,F,A}, Args, Timeout);
                            Other ->
				logger:info("trpc: safe token failed with ~p~n",[Other]),
                                throw({protocol_error, Other})
                        end;
                    {error, R} ->
			logger:error("trpc: server provided token received is an unsafe term. ~p~n",[R]),
                        throw({recv_failed, R})
                end
        end
    catch
        throw:Why -> {error, Why};
        Class:Term:Stack ->
            %% if anything crashes, don’t leave the TLS socket dangling
            catch ssl:close(Sock),
            {error, {client_after_tls_crash, Class, Term, Stack}}
    end.

-doc "Purpose:\n"
     "Sends a remote request after TLS/token setup and, for CALL requests, waits for the result. "
     "Constructs a request frame with a unique request id, transmits it, and for CALL expects a "
     "RESULT frame; CAST returns immediately.\n"
     "\n"
     "Parameters:\n"
     "- `CallType :: call | cast` — operation type controlling reply behavior.\n"
     "- `Sock :: ssl:sslsocket()` — established TLS socket.\n"
     "- `{M,F,A} :: {module(), atom(), non_neg_integer()}` — target module, function, and arity.\n"
     "- `Args :: [term()]` — arguments list; its length must equal `A`.\n"
     "- `Timeout :: integer()` — timeout in milliseconds for result reception (CALL only).\n"
     "\n"
     "Return Value:\n"
     "- `{ok, term()}` — successful result value (CALL).\n"
     "- `{ok, cast}` — acknowledgment that the cast was sent (CAST).\n"
     "- `{error, protocol_error}` — malformed or unexpected response frame (CALL).\n"
     "- `{error, closed}` — socket was closed by the peer before a result arrived (CALL).\n"
     "- `{error, timeout}` — no response within the timeout (CALL).\n"
     "- `Other :: term()` — any other error propagated unchanged from lower layers (CALL).\n"
     "\n"
     "Author: Lee Barney\n"
     "Version: 0.1\n"
     "\n"
     "Complexity:\n"
     "- Time: O(n)\n"
     "- Space: O(n)\n"
     "\n"
     "Last Modified: 2025-09-04\n".

-spec send_and_maybe_wait(
          call | cast,
          ssl:sslsocket(),
          {module(), atom(), non_neg_integer()},
          [term()],
          integer()
      ) ->
          {ok, term()}
        | {ok, cast}
        | {error, protocol_error}
        | {error, closed}
        | {error, timeout}
        | term().
send_and_maybe_wait(CallType, Sock, {M,F,A}, Args, Timeout) when length(Args) =:= A ->
    ReqId = crypto:strong_rand_bytes(12),
    Request = #{t => CallType, ver => 1, req_id => ReqId, m => M, f => F, a => A, args => Args, opts => #{timeout => Timeout}},
    logger:info("trpc: about to send request ~p~n",[Request]),
    ok = semp_util:send_frame(Sock, term_to_binary(Request)),
    case CallType of
	    call ->
    		%% Success: RESULT frame; else server closes silently.
    		logger:info("trpc: waiting for result~n"),
    		case semp_util:recv_frame(Sock, Timeout) of
        		{ok, Bin} ->
				logger:info("trpc: recieved result binary~n"),
            			case safe_term(Bin) of
                			#{t := result,  value := Val} -> 
						logger:info("trpc: got result ~p~n",[Val]),
						{ok, Val};
                			_ -> {error, protocol_error}
            			end;
        		{error, closed} -> {error, closed};
        		{error, timeout} -> {error, timeout};
        	Other -> Other
    		end;
	    cast ->
		{ok, cast}
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
        %% Always strict verification:
	{verify, verify_peer}
    ] ++ case SNI of 
		 undefined -> []; 
		 Host -> [{server_name_indication, Host}] 
	 end,
    Base ++ application:get_env(trust, client_tls_opts, []).

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
    ets:insert(?CACHE, {FP, Token}).


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
        [{Token}] -> Token;
        [] -> error;
	FailReason -> logger:error("trpc: token search failure reason ~p~n",[FailReason]),
		      error
    end.

